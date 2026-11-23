// A pretend gateway for tests: answers fetch() calls from a table of routes
// and remembers every request, so tests can check what the page sent.

import { vi } from "vitest";
import type { AuditEvent, Stats, TimelinePoint } from "../types";

export interface SentRequest {
  method: string;
  path: string;
  query: URLSearchParams;
  headers: Record<string, string>;
  body: unknown;
  credentials: RequestCredentials | undefined;
}

type Reply = { status?: number; body: unknown } | ((request: SentRequest) => { status?: number; body: unknown });

export function fakeGateway(routes: Record<string, Reply>) {
  const sent: SentRequest[] = [];
  const fetchMock = vi.fn(async (url: string, init: RequestInit = {}) => {
    const parsed = new URL(url, "http://dashboard.test");
    const request: SentRequest = {
      method: init.method ?? "GET",
      path: parsed.pathname,
      query: parsed.searchParams,
      headers: (init.headers ?? {}) as Record<string, string>,
      body: init.body ? JSON.parse(String(init.body)) : undefined,
      credentials: init.credentials,
    };
    sent.push(request);
    const route = routes[`${request.method} ${request.path}`];
    if (!route) {
      return json(404, { error: { code: "not_found", message: "Not found.", request_id: "req-404" } });
    }
    const reply = typeof route === "function" ? route(request) : route;
    return json(reply.status ?? 200, reply.body);
  });
  vi.stubGlobal("fetch", fetchMock);
  return { sent, fetchMock };
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "X-Request-ID": "req-test" },
  });
}

export const STATS: Stats = {
  total_events: 120,
  by_status: { completed: 100, input_blocked: 12, output_blocked: 3, scan_only: 5 },
  by_risk: { none: 80, low: 10, medium: 15, high: 10, critical: 5 },
  by_input_action: { allow: 90, redact: 18, block: 12 },
  by_output_action: { allow: 95, redact: 2, block: 3 },
  by_finding_type: { EMAIL_ADDRESS: 20, instruction_override: 9, AWS_ACCESS_KEY: 4 },
  events_by_detector: { pii: 22, injection: 9, secret: 4 },
  failed_writes: 0,
};

export function timeline(hours = 3): TimelinePoint[] {
  return Array.from({ length: hours }, (_, n) => ({
    start: new Date(Date.UTC(2026, 10, 20, n)).toISOString(),
    total: n === hours - 1 ? 6 : 0,
    by_risk: { none: n === hours - 1 ? 3 : 0, low: 0, medium: n === hours - 1 ? 2 : 0, high: 0, critical: n === hours - 1 ? 1 : 0 },
  }));
}

export function auditEvent(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    request_id: "req-abc123",
    timestamp: "2026-11-20T10:00:00Z",
    client_id: "client-1",
    policy_version: 2,
    provider: "mock",
    model: "mock-echo-1",
    input_action: "redact",
    output_action: "allow",
    risk_level: "medium",
    status: "completed",
    input_chars: 40,
    output_chars: 80,
    scan_ms: 21.4,
    provider_ms: 3.2,
    total_ms: 26.9,
    redacted_prompt: null,
    findings: [
      {
        direction: "input",
        detector: "pii",
        category: "personal_data",
        location: "messages[0]",
        entity_type: "EMAIL_ADDRESS",
        rule_id: null,
        confidence: 0.95,
        severity: "medium",
        span_start: 5,
        span_end: 22,
        fingerprint: "fp_0123456789abcdef",
      },
    ],
    ...overrides,
  };
}

export const POLICY_TEXT = "version: 1\nrules: []\n";

export const ADMIN_KEY = "lsg_test-admin-key";
