import { formatNumber, words } from "../format";

/** A simple list of horizontal bars, biggest first (one colour: one series). */
export function BarList({ counts, limit = 8 }: { counts: Record<string, number>; limit?: number }) {
  const rows = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit);
  if (rows.length === 0) return <p className="text-sm text-muted">Nothing found in this period</p>;
  const biggest = rows[0]?.[1] ?? 1;
  return (
    <ul className="space-y-2">
      {rows.map(([name, count]) => (
        <li key={name} className="text-sm">
          <div className="flex justify-between gap-2">
            <span className="truncate">{words(name)}</span>
            <span className="tabular text-ink-2">{formatNumber(count)}</span>
          </div>
          <div className="mt-1 h-1.5 rounded-full bg-line">
            <div className="h-1.5 rounded-full bg-accent" style={{ width: `${(count / biggest) * 100}%` }} />
          </div>
        </li>
      ))}
    </ul>
  );
}
