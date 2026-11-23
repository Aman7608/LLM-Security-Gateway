import type { ReactNode } from "react";
import type { Action, RiskLevel } from "../types";
import { words } from "../format";

export function Card({ title, children, actions }: { title: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="rounded-lg border border-line bg-surface p-4">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <h2 className="text-sm font-semibold">{title}</h2>
        {actions && <div className="ml-auto">{actions}</div>}
      </div>
      {children}
    </section>
  );
}

export function ErrorBox({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="rounded border border-bad/40 px-3 py-2 text-sm text-bad">
      {message}
      {onRetry && (
        <button type="button" onClick={onRetry} className="ml-3 underline">
          Try again
        </button>
      )}
    </div>
  );
}

export function Loading() {
  return <p className="text-sm text-muted">Loading...</p>;
}

/** A coloured square plus the word: the colour never carries the meaning alone. */
export function RiskBadge({ level }: { level: RiskLevel }) {
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
      <span aria-hidden className="inline-block size-2.5 rounded-sm" style={{ background: `var(--risk-${level})` }} />
      {level}
    </span>
  );
}

const ACTION_STYLE: Record<Action, string> = {
  allow: "text-ink-2",
  warn: "text-ink",
  redact: "text-ink font-medium",
  block: "text-bad font-semibold",
};

export function ActionText({ action }: { action: Action | null }) {
  if (!action) return <span className="text-muted">-</span>;
  return <span className={ACTION_STYLE[action]}>{words(action)}</span>;
}

export const selectClass = "rounded border border-axis bg-page px-2 py-1.5 text-sm";
export const buttonClass =
  "rounded border border-axis px-3 py-1.5 text-sm hover:bg-line/60 disabled:cursor-not-allowed disabled:opacity-50";
