// Talks to the gateway API. Every call sends the admin key in X-API-Key.
//
// The key is only kept in memory (React state), never in localStorage or a
// cookie. Closing or reloading the tab forgets it, so a key cannot be left
// behind on a shared computer or read later by other code on this site.

import type {
  ActivePolicy,
  EventsReply,
  AuditEvent,
  SavedPolicy,
  Stats,
  TimelinePoint,
  ValidateReply,
} from "./types";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string | null;

  constructor(status: number, code: string, message: string, requestId: string | null) {
    super(message);
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

type Query = Record<string, string | number | undefined>;

export class GatewayApi {
  private readonly key: string;

  constructor(key: string) {
    this.key = key;
  }

  stats(since?: string): Promise<Stats> {
    return this.call("GET", "/v1/stats", { since });
  }

  timeline(hours: number, step: "hour" | "day"): Promise<TimelinePoint[]> {
    return this.call("GET", "/v1/stats/timeline", { hours, step });
  }

  events(filters: Query): Promise<EventsReply> {
    return this.call("GET", "/v1/events", filters);
  }

  event(requestId: string): Promise<AuditEvent> {
    return this.call("GET", `/v1/events/${encodeURIComponent(requestId)}`);
  }

  activePolicy(): Promise<ActivePolicy> {
    return this.call("GET", "/v1/policies/active");
  }

  validatePolicy(policy: string): Promise<ValidateReply> {
    return this.call("POST", "/v1/policies/validate", undefined, { policy });
  }

  savePolicy(policy: string): Promise<ActivePolicy> {
    return this.call("PUT", "/v1/policies/active", undefined, { policy });
  }

  policyHistory(): Promise<SavedPolicy[]> {
    return this.call("GET", "/v1/policies/history");
  }

  private async call<T>(method: string, path: string, query?: Query, body?: unknown): Promise<T> {
    const params = new URLSearchParams();
    for (const [name, value] of Object.entries(query ?? {})) {
      if (value !== undefined && value !== "") params.set(name, String(value));
    }
    const url = params.size ? `${path}?${params}` : path;
    const headers: Record<string, string> = { "X-API-Key": this.key };
    if (body !== undefined) headers["Content-Type"] = "application/json";

    let response: Response;
    try {
      response = await fetch(url, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        credentials: "omit", // we use the key header, never cookies
        cache: "no-store",
      });
    } catch {
      throw new ApiError(0, "network_error", "The gateway could not be reached. Is it running?", null);
    }
    const data: unknown = await response.json().catch(() => null);
    if (!response.ok) throw toApiError(response, data);
    return data as T;
  }
}

function toApiError(response: Response, data: unknown): ApiError {
  // The gateway always answers errors as {"error": {code, message, request_id}}
  const error = (data as { error?: { code?: string; message?: string; request_id?: string } } | null)
    ?.error;
  return new ApiError(
    response.status,
    error?.code ?? "unknown_error",
    error?.message ?? `The gateway answered with status ${response.status}.`,
    error?.request_id ?? response.headers.get("x-request-id"),
  );
}

/** A short message for the screen, with the reference id if there is one. */
export function describeError(error: unknown): string {
  if (error instanceof ApiError) {
    return error.requestId ? `${error.message} (reference ${error.requestId})` : error.message;
  }
  return "Something went wrong.";
}
