import { useCallback, useState, type FormEvent, type ReactNode } from "react";
import type { GatewayApi } from "../api";
import { ActionText, Card, ErrorBox, Loading, RiskBadge, buttonClass, selectClass } from "../components/ui";
import { formatNumber, formatTime, words } from "../format";
import { ACTIONS, RISK_LEVELS, STATUSES } from "../types";
import { useLoad } from "../useLoad";

const PAGE_SIZE = 25;

interface Filters {
  min_risk: string;
  action: string;
  status: string;
  finding_type: string;
}

const NO_FILTERS: Filters = { min_risk: "", action: "", status: "", finding_type: "" };

export function EventsPage({ api }: { api: GatewayApi }) {
  const [filters, setFilters] = useState<Filters>(NO_FILTERS);
  const [draftType, setDraftType] = useState("");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);

  const events = useLoad(
    useCallback(() => api.events({ ...filters, limit: PAGE_SIZE, offset }), [api, filters, offset]),
  );

  function change(name: keyof Filters, value: string) {
    setFilters((old) => ({ ...old, [name]: value }));
    setOffset(0);
  }

  function searchType(event: FormEvent) {
    event.preventDefault();
    change("finding_type", draftType.trim());
  }

  const total = events.data?.total ?? 0;

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">Security events</h2>

      <div className="flex flex-wrap items-end gap-3 text-sm">
        <Choice label="Risk" value={filters.min_risk} onChange={(v) => change("min_risk", v)}
          options={RISK_LEVELS.filter((r) => r !== "none").map((r) => [r, `${r} or higher`])} />
        <Choice label="Decision" value={filters.action} onChange={(v) => change("action", v)}
          options={ACTIONS.map((a) => [a, a])} />
        <Choice label="Status" value={filters.status} onChange={(v) => change("status", v)}
          options={STATUSES.map((s) => [s, words(s)])} />
        <form onSubmit={searchType} className="flex items-end gap-2">
          <label className="flex flex-col gap-1 text-ink-2">
            Finding type
            <input
              value={draftType}
              onChange={(event) => setDraftType(event.target.value)}
              placeholder="e.g. EMAIL_ADDRESS"
              className={`${selectClass} w-44`}
            />
          </label>
          <button type="submit" className={buttonClass}>
            Search
          </button>
        </form>
        {(filters !== NO_FILTERS || draftType) && (
          <button
            type="button"
            className="py-1.5 text-ink-2 underline"
            onClick={() => {
              setFilters(NO_FILTERS);
              setDraftType("");
              setOffset(0);
            }}
          >
            Clear filters
          </button>
        )}
      </div>

      {events.error && <ErrorBox message={events.error} onRetry={events.reload} />}

      <Card
        title={events.data ? `${formatNumber(total)} events` : "Events"}
        actions={
          <div className="flex items-center gap-2 text-sm">
            <button type="button" className={buttonClass} disabled={offset === 0}
              onClick={() => setOffset(Math.max(offset - PAGE_SIZE, 0))}>
              Newer
            </button>
            <span className="tabular text-ink-2">
              {total === 0 ? "0" : `${offset + 1}-${Math.min(offset + PAGE_SIZE, total)}`}
            </span>
            <button type="button" className={buttonClass} disabled={offset + PAGE_SIZE >= total}
              onClick={() => setOffset(offset + PAGE_SIZE)}>
              Older
            </button>
          </div>
        }
      >
        {events.loading && !events.data ? (
          <Loading />
        ) : events.data && events.data.items.length === 0 ? (
          <p className="text-sm text-muted">No events match these filters.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-ink-2">
                <tr>
                  <th className="py-2 pr-3 font-medium">Time</th>
                  <th className="py-2 pr-3 font-medium">Request id</th>
                  <th className="py-2 pr-3 font-medium">Status</th>
                  <th className="py-2 pr-3 font-medium">Prompt</th>
                  <th className="py-2 pr-3 font-medium">Answer</th>
                  <th className="py-2 pr-3 font-medium">Risk</th>
                  <th className="py-2 pr-3 text-right font-medium">Findings</th>
                  <th className="py-2 text-right font-medium">Time taken</th>
                </tr>
              </thead>
              <tbody>
                {events.data?.items.map((item) => (
                  <tr
                    key={item.request_id}
                    className={`cursor-pointer border-t border-line hover:bg-line/40 ${
                      selected === item.request_id ? "bg-accent/10" : ""
                    }`}
                    onClick={() => setSelected(item.request_id)}
                  >
                    <td className="py-2 pr-3 whitespace-nowrap">{formatTime(item.timestamp)}</td>
                    <td className="py-2 pr-3">
                      {/* A real button, so the row can be opened with the keyboard too */}
                      <button type="button" className="font-mono text-xs underline" onClick={() => setSelected(item.request_id)}>
                        {item.request_id}
                      </button>
                    </td>
                    <td className="py-2 pr-3 whitespace-nowrap">{words(item.status)}</td>
                    <td className="py-2 pr-3"><ActionText action={item.input_action} /></td>
                    <td className="py-2 pr-3"><ActionText action={item.output_action} /></td>
                    <td className="py-2 pr-3"><RiskBadge level={item.risk_level} /></td>
                    <td className="tabular py-2 pr-3 text-right">{item.findings.length}</td>
                    <td className="tabular py-2 text-right whitespace-nowrap">{Math.round(item.total_ms)} ms</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {selected && <EventDetail api={api} requestId={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

function Choice({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: [string, string][];
}) {
  return (
    <label className="flex flex-col gap-1 text-ink-2">
      {label}
      <select className={selectClass} value={value} onChange={(event) => onChange(event.target.value)}>
        <option value="">Any</option>
        {options.map(([optionValue, text]) => (
          <option key={optionValue} value={optionValue}>
            {text}
          </option>
        ))}
      </select>
    </label>
  );
}

function EventDetail({ api, requestId, onClose }: { api: GatewayApi; requestId: string; onClose: () => void }) {
  const event = useLoad(useCallback(() => api.event(requestId), [api, requestId]));
  const data = event.data;

  return (
    <Card
      title={`Event ${requestId}`}
      actions={
        <button type="button" className={buttonClass} onClick={onClose}>
          Close
        </button>
      }
    >
      {event.error && <ErrorBox message={event.error} />}
      {!data || data.request_id !== requestId ? (
        !event.error && <Loading />
      ) : (
        <div className="space-y-4 text-sm">
          <dl className="grid grid-cols-2 gap-x-6 gap-y-2 sm:grid-cols-4">
            <Fact name="Time" value={formatTime(data.timestamp)} />
            <Fact name="Status" value={words(data.status)} />
            <Fact name="Risk" value={<RiskBadge level={data.risk_level} />} />
            <Fact name="Policy version" value={data.policy_version ?? "-"} />
            <Fact name="Prompt decision" value={<ActionText action={data.input_action} />} />
            <Fact name="Answer decision" value={<ActionText action={data.output_action} />} />
            <Fact name="Provider" value={data.provider ? `${data.provider} / ${data.model ?? "-"}` : "-"} />
            <Fact name="Client" value={data.client_id ?? "-"} />
            <Fact name="Prompt size" value={`${formatNumber(data.input_chars)} characters`} />
            <Fact name="Answer size" value={`${formatNumber(data.output_chars)} characters`} />
            <Fact name="Scanning" value={`${Math.round(data.scan_ms)} ms`} />
            <Fact name="Total" value={`${Math.round(data.total_ms)} ms`} />
          </dl>

          <div>
            <h3 className="mb-1 font-medium">Findings</h3>
            {data.findings.length === 0 ? (
              <p className="text-muted">Nothing was found.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="text-ink-2">
                    <tr>
                      {["Where", "Detector", "Type", "Rule", "Severity", "Confidence", "Position", "Fingerprint"].map(
                        (heading) => (
                          <th key={heading} className="py-1 pr-3 font-medium">
                            {heading}
                          </th>
                        ),
                      )}
                    </tr>
                  </thead>
                  <tbody>
                    {data.findings.map((finding, n) => (
                      <tr key={n} className="border-t border-line">
                        <td className="py-1 pr-3">{finding.location ?? finding.direction}</td>
                        <td className="py-1 pr-3">{finding.detector}</td>
                        <td className="py-1 pr-3">{finding.entity_type ?? words(finding.category)}</td>
                        <td className="py-1 pr-3 font-mono">{finding.rule_id ?? "-"}</td>
                        <td className="py-1 pr-3"><RiskBadge level={finding.severity} /></td>
                        <td className="tabular py-1 pr-3">{finding.confidence.toFixed(2)}</td>
                        <td className="tabular py-1 pr-3">
                          {finding.span_start}-{finding.span_end}
                        </td>
                        <td className="py-1 font-mono">{finding.fingerprint ?? "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <p className="mt-2 text-xs text-muted">
              The log never keeps the found values. The fingerprint lets you see when the same value shows up again.
            </p>
          </div>

          <div>
            <h3 className="mb-1 font-medium">Saved prompt</h3>
            {data.redacted_prompt === null ? (
              <p className="text-muted">Not saved (prompt saving is off, or the prompt was blocked).</p>
            ) : (
              // Shown as plain text. React escapes it, so text from an attacker
              // can never run as code in this page.
              <pre className="max-h-60 overflow-auto rounded bg-page p-3 text-xs whitespace-pre-wrap">
                {data.redacted_prompt}
              </pre>
            )}
          </div>
        </div>
      )}
    </Card>
  );
}

function Fact({ name, value }: { name: string; value: ReactNode }) {
  return (
    <div>
      <dt className="text-xs text-ink-2">{name}</dt>
      <dd>{value}</dd>
    </div>
  );
}
