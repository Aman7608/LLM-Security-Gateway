"""Routes for apps (any valid API key): chat, scan and providers."""

from __future__ import annotations

from fastapi import APIRouter, Request

from llm_gateway.api.auth import Client, GatewayDep
from llm_gateway.api.errors import ApiError
from llm_gateway.api.schemas import (
    ERRORS,
    ChatBody,
    ChatReply,
    FindingOut,
    ProvidersReply,
    ScanBody,
    ScanReply,
    SecuritySummary,
)
from llm_gateway.audit.logger import AuditWriteError
from llm_gateway.core.gateway import (
    InvalidChatRequest,
    PromptBlocked,
    RequestTooLarge,
)
from llm_gateway.models import Action
from llm_gateway.providers.base import (
    ProviderError,
    ProviderNotConfigured,
    ProviderTimeout,
)

router = APIRouter(prefix="/v1")


@router.post("/chat", tags=["chat"], responses=ERRORS)
async def chat(
    body: ChatBody, request: Request, client: Client, gateway: GatewayDep
) -> ChatReply:
    """Send a conversation through the full gateway.

    The prompt is checked first. A blocked prompt gets **403** and the AI is
    never called. Otherwise the redacted prompt goes to the AI, the answer
    is checked, and you get **200**. A withheld answer still gives 200,
    with `blocked: true` and a neutral message in `content`.
    """
    request_id: str = request.state.request_id
    try:
        outcome = await gateway.chat(
            request_id,
            body.messages,
            body.documents,
            provider=body.provider,
            model=body.model,
            max_tokens=body.max_tokens,
            client_id=client.id,
        )
    except PromptBlocked as blocked:
        raise ApiError(
            403,
            "request_blocked",
            "The request was blocked by the security policy.",
            details={"categories": blocked.categories},
        ) from None
    except ProviderNotConfigured as error:
        raise ApiError(
            400,
            "provider_not_configured",
            f"The provider '{error.provider}' is not set up. "
            "GET /v1/providers lists the ready ones.",
        ) from None
    except ProviderTimeout:
        raise ApiError(
            504, "provider_timeout", "The AI provider did not answer in time."
        ) from None
    except ProviderError:
        # The provider's own message is never passed on (it can hold account
        # details); our log and the audit record have what admins need
        raise ApiError(
            502, "provider_error", "The AI provider could not answer."
        ) from None
    except RequestTooLarge as error:
        raise ApiError(413, "request_too_large", str(error)) from None
    except InvalidChatRequest as error:
        raise ApiError(422, "invalid_request", str(error)) from None
    except AuditWriteError:
        raise _audit_unavailable() from None

    guarded = outcome.guarded
    return ChatReply(
        request_id=request_id,
        provider=outcome.answer.provider,
        model=outcome.answer.model,
        content=guarded.text,
        finish_reason=guarded.finish_reason,
        blocked=guarded.blocked,
        redacted=guarded.redacted,
        usage=outcome.answer.usage,
        security=SecuritySummary(
            prompt_action=outcome.prompt_action,
            answer_action=guarded.action,
            risk_level=outcome.record.risk_level,
            hidden=outcome.hidden,
            warnings=outcome.warnings,
        ),
    )


@router.post("/scan", tags=["scan"], responses=ERRORS)
async def scan(
    body: ScanBody, request: Request, client: Client, gateway: GatewayDep
) -> ScanReply:
    """Only check text, without calling any AI.

    Use `direction: "output"` to check text as if it were an AI answer
    (with `system_prompt`, copies of it are found too).
    """
    request_id: str = request.state.request_id
    try:
        outcome = await gateway.scan(
            request_id, body.text, body.direction, body.system_prompt, client.id
        )
    except AuditWriteError:
        raise _audit_unavailable() from None
    result = outcome.result
    return ScanReply(
        request_id=request_id,
        direction=body.direction,
        action=result.action,
        risk_level=result.decision.risk_level,
        allowed=result.action is not Action.BLOCK,
        text=result.output_text,
        findings=[
            FindingOut(
                category=f.category,
                entity_type=f.entity_type,
                start=f.start,
                end=f.end,
                confidence=f.confidence,
                severity=f.severity,
            )
            for f in result.scan.findings
        ],
    )


@router.get("/providers", tags=["chat"], responses=ERRORS)
def providers(client: Client, gateway: GatewayDep) -> ProvidersReply:
    """The AI providers that are set up, and why the others are not."""
    return ProvidersReply(
        default=gateway.registry.default, providers=gateway.registry.describe()
    )


def _audit_unavailable() -> ApiError:
    return ApiError(
        503,
        "audit_unavailable",
        "The request could not be recorded, so it was refused "
        "(GATEWAY_AUDIT_REQUIRED is on).",
    )
