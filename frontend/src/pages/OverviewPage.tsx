import { useCallback, useState } from "react";
import type { GatewayApi } from "../api";
import { BarList } from "../components/BarList";
import { RiskChart } from "../components/RiskChart";
import { Card, ErrorBox, Loading, selectClass } from "../components/ui";
import { formatNumber, hoursAgo } from "../format";
import type { Stats } from "../types";
import { useLoad } from "../useLoad";

const RANGES = [
  { label: "Last 24 hours", hours: 24, step: "hour" },
  { label: "Last 7 days", hours: 24 * 7, step: "day" },
  { label: "Last 30 days", hours: 24 * 30, step: "day" },
] as const;

export function OverviewPage({ api }: { api: GatewayApi }) {
  const [rangeIndex, setRangeIndex] = useState(0);
  const range = RANGES[rangeIndex] ?? RANGES[0];

  const stats = useLoad(useCallback(() => api.stats(hoursAgo(range.hours)), [api, range.hours]));
  const timeline = useLoad(useCallback(() => api.timeline(range.hours, range.step), [api, range.hours, range.step]));

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-lg font-semibold">Overview</h2>
        <label className="ml-auto flex items-center gap-2 text-sm text-ink-2">
          Period
          <select
            className={selectClass}
            value={rangeIndex}
            onChange={(event) => setRangeIndex(Number(event.target.value))}
          >
            {RANGES.map((option, n) => (
              <option key={option.label} value={n}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <button
          type="button"
          className="rounded px-2 py-1.5 text-sm text-ink-2 underline"
          onClick={() => {
            stats.reload();
            timeline.reload();
          }}
        >
          Refresh
        </button>
      </div>

      {stats.error && <ErrorBox message={stats.error} onRetry={stats.reload} />}
      {stats.data ? <Totals stats={stats.data} /> : !stats.error && <Loading />}

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="min-w-0 lg:col-span-2">
          <Card title="Events by risk level">
            {timeline.error && <ErrorBox message={timeline.error} onRetry={timeline.reload} />}
            {timeline.data ? <RiskChart points={timeline.data} step={range.step} /> : !timeline.error && <Loading />}
          </Card>
        </div>
        <Card title="Most found types">
          {stats.data ? <BarList counts={stats.data.by_finding_type} /> : <Loading />}
        </Card>
      </div>
    </div>
  );
}

/** The headline numbers (FR-55). */
export function Totals({ stats }: { stats: Stats }) {
  const blocked = (stats.by_input_action.block ?? 0) + (stats.by_output_action.block ?? 0);
  const tiles = [
    { label: "Requests", value: stats.total_events },
    { label: "Blocked", value: blocked, note: "prompts or answers" },
    { label: "Prompt injection", value: stats.events_by_detector.injection ?? 0, note: "requests" },
    { label: "Personal data", value: stats.events_by_detector.pii ?? 0, note: "requests" },
    { label: "Secrets", value: stats.events_by_detector.secret ?? 0, note: "requests" },
  ];
  return (
    <div className="space-y-3">
      {stats.failed_writes > 0 && (
        <p role="alert" className="rounded bg-warn-bg px-3 py-2 text-sm">
          Warning: {formatNumber(stats.failed_writes)} audit records could not be saved to the database since the
          gateway started. They were written to the server log instead.
        </p>
      )}
      <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        {tiles.map((tile) => (
          <div key={tile.label} className="rounded-lg border border-line bg-surface p-4">
            <dt className="text-sm text-ink-2">{tile.label}</dt>
            <dd className="mt-1 text-2xl font-semibold">{formatNumber(tile.value)}</dd>
            {tile.note && <dd className="text-xs text-muted">{tile.note}</dd>}
          </div>
        ))}
      </dl>
    </div>
  );
}
