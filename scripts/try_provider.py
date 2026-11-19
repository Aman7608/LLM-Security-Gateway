"""Send one prompt to an AI provider, optionally through the gateway's checks.

Examples, run from the project folder with .\\.venv\\Scripts\\python.exe:

    # The free, offline mock provider
    python scripts\\try_provider.py "Hello there"

    # Through the full DLP engine: the prompt is checked before it is sent,
    # and the answer is checked before it is shown
    python scripts\\try_provider.py --protect "Email priya@example.com"
    python scripts\\try_provider.py --protect "[mock:leak-secret]"

    # A real provider (costs money; needs your key in .env and
    # pip install -r requirements-providers.txt)
    python scripts\\try_provider.py --provider anthropic "Say hi"

Your API keys are read from .env (GATEWAY_OPENAI_API_KEY, GATEWAY_ANTHROPIC_API_KEY)
and are never printed.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from llm_gateway.core.factory import build_dlp_engine
from llm_gateway.dlp.engine import DLPResult
from llm_gateway.models import Direction
from llm_gateway.providers.base import ChatMessage, ChatRequest, ProviderError
from llm_gateway.providers.registry import ProviderRegistry
from llm_gateway.settings import get_settings


def show(label: str, checked: DLPResult) -> None:
    """Print what the DLP engine decided, and why."""
    risk = checked.decision.risk_level.value
    print(f"[{label}] {checked.action.value}, risk {risk}")
    for reason in checked.decision.reasons:
        print(f"   {reason}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("prompt", help="what to ask")
    parser.add_argument(
        "--provider", help="mock, openai or anthropic (default: settings)"
    )
    parser.add_argument("--model", help="use a different model than the default")
    parser.add_argument(
        "--protect",
        action="store_true",
        help="check the prompt and answer with the DLP engine",
    )
    args = parser.parse_args()

    settings = get_settings()
    registry = ProviderRegistry.from_settings(settings)
    try:
        provider = registry.get(args.provider)
    except ProviderError as error:
        print(f"Cannot use that provider: {error}")
        print("Ready providers:", ", ".join(registry.available))
        return 1

    prompt = args.prompt
    engine = build_dlp_engine(settings) if args.protect else None
    if engine:
        checked = engine.process(prompt, Direction.INPUT)
        show("prompt check", checked)
        if checked.output_text is None:
            print("The prompt was blocked, so nothing was sent to the AI.")
            return 0
        prompt = checked.output_text
        print(f"[sent to the AI] {prompt}")

    request = ChatRequest(
        messages=[ChatMessage(role="user", content=prompt)], model=args.model
    )
    try:
        answer = asyncio.run(provider.complete(request))
    except ProviderError as error:
        print(f"The provider failed: {error}")
        return 1

    print(
        f"[{answer.provider} / {answer.model}] finish={answer.finish_reason.value} "
        f"tokens in/out={answer.usage.input_tokens}/{answer.usage.output_tokens} "
        f"attempts={answer.attempts} time={answer.latency_ms:.0f} ms"
    )
    text = answer.content
    if engine:
        checked = engine.process(text, Direction.OUTPUT)
        show("answer check", checked)
        if checked.output_text is None:
            print("The answer was withheld by the gateway.")
            return 0
        text = checked.output_text
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
