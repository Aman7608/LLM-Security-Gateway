// The shapes the gateway API sends back (see src/llm_gateway/api/ in Python)

export const RISK_LEVELS = ["none", "low", "medium", "high", "critical"] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];

export const ACTIONS = ["allow", "warn", "redact", "block"] as const;
export type Action = (typeof ACTIONS)[number];

export const STATUSES = [
  "completed",
  "input_blocked",
  "output_blocked",
  "provider_error",
  "scan_only",
] as const;
export type EventStatus = (typeof STATUSES)[number];

export interface Stats {
  total_events: number;
  by_status: Record<string, number>;
  by_risk: Record<string, number>;
  by_input_action: Record<string, number>;
  by_output_action: Record<string, number>;
  by_finding_type: Record<string, number>;
  events_by_detector: Record<string, number>;
  failed_writes: number;
}

export interface TimelinePoint {
  start: string;
  total: number;
  by_risk: Record<RiskLevel, number>;
}

export interface Finding {
  direction: "input" | "output";
  detector: string;
  category: string;
  location: string | null;
  entity_type: string | null;
  rule_id: string | null;
  confidence: number;
  severity: RiskLevel;
  span_start: number;
  span_end: number;
  fingerprint: string | null;
}

export interface AuditEvent {
  request_id: string;
  timestamp: string;
  client_id: string | null;
  policy_version: number | null;
  provider: string | null;
  model: string | null;
  input_action: Action;
  output_action: Action | null;
  risk_level: RiskLevel;
  status: EventStatus;
  input_chars: number;
  output_chars: number;
  scan_ms: number;
  provider_ms: number;
  total_ms: number;
  redacted_prompt: string | null;
  findings: Finding[];
}

export interface EventsReply {
  total: number;
  limit: number;
  offset: number;
  items: AuditEvent[];
}

export interface ActivePolicy {
  version: number;
  checksum: string;
  created_by: string;
  source: string;
  created_at: string;
  text: string;
}

export interface SavedPolicy {
  version: number;
  checksum: string;
  created_by: string;
  source: string;
  created_at: string;
  active: boolean;
}

export interface ValidateReply {
  valid: boolean;
  problem: string | null;
}
