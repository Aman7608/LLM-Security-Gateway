// Stacked bars: how many events per hour (or day), split by risk level.
// Drawn with plain SVG instead of a chart library, so the dashboard needs
// fewer outside packages (fewer things that could break or be attacked).

import { useCallback, useEffect, useRef, useState } from "react";
import { RISK_LEVELS, type TimelinePoint } from "../types";
import { formatNumber } from "../format";

interface Props {
  points: TimelinePoint[];
  step: "hour" | "day";
}

const HEIGHT = 220;
const MARGIN = { top: 8, right: 8, bottom: 26, left: 40 };

export function RiskChart({ points, step }: Props) {
  const [box, width] = useWidth();
  const [hovered, setHovered] = useState<number | null>(null);
  const [showTable, setShowTable] = useState(false);

  const innerW = Math.max(width - MARGIN.left - MARGIN.right, 50);
  const innerH = HEIGHT - MARGIN.top - MARGIN.bottom;
  const top = niceMax(Math.max(0, ...points.map((p) => p.total)));
  const band = innerW / Math.max(points.length, 1);
  const barW = Math.max(Math.min(band * 0.7, 28), 2);
  const y = (value: number) => innerH - (value / top) * innerH;
  const labelEvery = Math.ceil(points.length / Math.max(Math.floor(innerW / 70), 1));
  const label = (iso: string) => formatTick(iso, step);
  const empty = points.every((p) => p.total === 0);

  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-ink-2">
        {RISK_LEVELS.map((level) => (
          <span key={level} className="inline-flex items-center gap-1.5">
            <span aria-hidden className="inline-block size-2.5 rounded-sm" style={{ background: `var(--risk-${level})` }} />
            {level}
          </span>
        ))}
        <button type="button" onClick={() => setShowTable((v) => !v)} className="ml-auto underline">
          {showTable ? "Show chart" : "Show as table"}
        </button>
      </div>

      {showTable ? (
        <TimelineTable points={points} label={label} />
      ) : (
        // min-w-0 and overflow-hidden: the box gets its width from the page,
        // never from the chart inside it (otherwise it could never shrink)
        <div ref={box} className="relative w-full min-w-0 overflow-hidden" onMouseLeave={() => setHovered(null)}>
          <svg
            className="block"
            width={width}
            height={HEIGHT}
            role="img"
            aria-label={`Events per ${step} by risk level. Use "Show as table" for the numbers.`}
          >
            <g transform={`translate(${MARGIN.left},${MARGIN.top})`}>
              {[0, top / 2, top].map((tick) => (
                <g key={tick} transform={`translate(0,${y(tick)})`}>
                  <line x2={innerW} stroke={tick === 0 ? "var(--axis)" : "var(--line)"} />
                  <text x={-8} dy="0.32em" textAnchor="end" className="tabular fill-muted text-[11px]">
                    {formatNumber(tick)}
                  </text>
                </g>
              ))}
              {points.map((point, n) => {
                const x = n * band + (band - barW) / 2;
                let below = 0;
                const filled = RISK_LEVELS.filter((level) => point.by_risk[level] > 0);
                return (
                  <g key={point.start}>
                    {filled.map((level, k) => {
                      const count = point.by_risk[level];
                      const y1 = y(below + count);
                      const h = y(below) - y1;
                      below += count;
                      const isTop = k === filled.length - 1;
                      return (
                        <path
                          key={level}
                          d={isTop ? roundedTop(x, y1, barW, h, 4) : `M${x},${y1}h${barW}v${h}h${-barW}Z`}
                          fill={`var(--risk-${level})`}
                          stroke="var(--surface)"
                          strokeWidth={1}
                          opacity={hovered === null || hovered === n ? 1 : 0.45}
                        />
                      );
                    })}
                    {n % labelEvery === 0 && (
                      <text x={n * band + band / 2} y={innerH + 18} textAnchor="middle" className="fill-muted text-[11px]">
                        {label(point.start)}
                      </text>
                    )}
                    {/* Wider than the bar, so it is easy to point at */}
                    <rect
                      data-testid="bar-target"
                      x={n * band}
                      width={band}
                      height={innerH}
                      fill="transparent"
                      onMouseEnter={() => setHovered(n)}
                    />
                  </g>
                );
              })}
            </g>
          </svg>
          {empty && (
            <p className="pointer-events-none absolute inset-0 grid place-items-center text-sm text-muted">
              No events in this period
            </p>
          )}
          {hovered !== null && points[hovered] && (
            <Tooltip
              point={points[hovered]}
              label={label(points[hovered].start)}
              left={Math.min(MARGIN.left + hovered * band + band, width - 170)}
            />
          )}
        </div>
      )}
    </div>
  );
}

function Tooltip({ point, label, left }: { point: TimelinePoint; label: string; left: number }) {
  return (
    <div
      role="status"
      className="pointer-events-none absolute top-2 w-40 rounded border border-line bg-surface p-2 text-xs shadow"
      style={{ left: Math.max(left, 0) }}
    >
      <p className="font-medium">{label}</p>
      {[...RISK_LEVELS].reverse().map((level) => (
        <p key={level} className="flex items-center gap-1.5 text-ink-2">
          <span aria-hidden className="inline-block size-2 rounded-sm" style={{ background: `var(--risk-${level})` }} />
          {level}
          <span className="tabular ml-auto text-ink">{formatNumber(point.by_risk[level])}</span>
        </p>
      ))}
      <p className="mt-1 flex border-t border-line pt-1">
        total <span className="tabular ml-auto font-medium">{formatNumber(point.total)}</span>
      </p>
    </div>
  );
}

function TimelineTable({ points, label }: { points: TimelinePoint[]; label: (iso: string) => string }) {
  return (
    <div className="max-h-72 overflow-auto">
      <table className="tabular w-full text-right text-xs">
        <thead className="sticky top-0 bg-surface text-ink-2">
          <tr>
            <th className="py-1 text-left font-medium">Time</th>
            {RISK_LEVELS.map((level) => (
              <th key={level} className="px-2 py-1 font-medium">
                {level}
              </th>
            ))}
            <th className="py-1 font-medium">total</th>
          </tr>
        </thead>
        <tbody>
          {points.map((point) => (
            <tr key={point.start} className="border-t border-line">
              <td className="py-1 text-left">{label(point.start)}</td>
              {RISK_LEVELS.map((level) => (
                <td key={level} className="px-2 py-1">
                  {point.by_risk[level]}
                </td>
              ))}
              <td className="py-1 font-medium">{point.total}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** A bar segment with its two top corners rounded. */
function roundedTop(x: number, y: number, w: number, h: number, radius: number): string {
  const r = Math.min(radius, w / 2, h);
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
}

/** Round the top of the scale up to 1, 2 or 5 times a power of ten. */
export function niceMax(value: number): number {
  if (value <= 1) return 1;
  const power = 10 ** Math.floor(Math.log10(value));
  const nice = [1, 2, 5, 10].find((m) => m * power >= value) ?? 10;
  return nice * power;
}

function formatTick(iso: string, step: "hour" | "day"): string {
  const date = new Date(iso);
  return step === "hour"
    ? date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })
    : date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

/** The width of the chart's box, kept up to date when the window changes. */
function useWidth(): [(node: HTMLDivElement | null) => void, number] {
  const [width, setWidth] = useState(720);
  const observer = useRef<ResizeObserver | null>(null);
  useEffect(() => () => observer.current?.disconnect(), []);
  const ref = useCallback((node: HTMLDivElement | null) => {
    observer.current?.disconnect();
    if (!node || typeof ResizeObserver === "undefined") return;
    observer.current = new ResizeObserver(([entry]) => {
      if (entry) setWidth(Math.round(entry.contentRect.width));
    });
    observer.current.observe(node);
  }, []);
  return [ref, width];
}
