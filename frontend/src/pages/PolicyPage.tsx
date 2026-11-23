import { useCallback, useState } from "react";
import { describeError, type GatewayApi } from "../api";
import { Card, ErrorBox, Loading, buttonClass } from "../components/ui";
import { formatTime } from "../format";
import type { ValidateReply } from "../types";
import { useLoad } from "../useLoad";

export function PolicyPage({ api }: { api: GatewayApi }) {
  const active = useLoad(useCallback(() => api.activePolicy(), [api]));
  const history = useLoad(useCallback(() => api.policyHistory(), [api]));

  // What the admin typed. null means "not edited": show the active policy.
  const [draft, setDraft] = useState<string | null>(null);
  const text = draft ?? active.data?.text ?? "";
  const [check, setCheck] = useState<ValidateReply | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  const changed = active.data !== null && text !== active.data.text;

  async function validate() {
    setBusy(true);
    setMessage(null);
    try {
      setCheck(await api.validatePolicy(text));
    } catch (error) {
      setMessage({ ok: false, text: describeError(error) });
    } finally {
      setBusy(false);
    }
  }

  async function save() {
    if (!window.confirm("Use this policy now? Every request from now on will be checked with it.")) return;
    setBusy(true);
    setMessage(null);
    try {
      const saved = await api.savePolicy(text);
      setMessage({ ok: true, text: `Saved. Policy version ${saved.version} is now in use.` });
      setCheck(null);
      setDraft(null);
      active.reload();
      history.reload();
    } catch (error) {
      // A broken policy is refused by the gateway, and nothing changes
      setMessage({ ok: false, text: describeError(error) });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">Security policy</h2>
      {active.error && <ErrorBox message={active.error} onRetry={active.reload} />}

      <Card
        title={active.data ? `Active policy: version ${active.data.version}` : "Active policy"}
        actions={
          active.data && (
            <span className="text-xs text-ink-2">
              from {active.data.source}, by {active.data.created_by}, {formatTime(active.data.created_at)}
            </span>
          )
        }
      >
        {!active.data ? (
          !active.error && <Loading />
        ) : (
          <div className="space-y-3">
            <label htmlFor="policy-text" className="sr-only">
              Policy (YAML)
            </label>
            <textarea
              id="policy-text"
              value={text}
              spellCheck={false}
              onChange={(event) => {
                setDraft(event.target.value);
                setCheck(null);
                setMessage(null);
              }}
              className="h-96 w-full rounded border border-axis bg-page p-3 font-mono text-xs"
            />
            <div className="flex flex-wrap items-center gap-2">
              <button type="button" className={buttonClass} disabled={busy} onClick={validate}>
                Check for mistakes
              </button>
              <button
                type="button"
                disabled={busy || !changed}
                onClick={save}
                className="rounded bg-accent px-3 py-1.5 text-sm font-medium text-white disabled:cursor-not-allowed disabled:opacity-50"
              >
                Save and use
              </button>
              {changed && (
                <button
                  type="button"
                  className="text-sm text-ink-2 underline"
                  onClick={() => {
                    setDraft(null);
                    setCheck(null);
                  }}
                >
                  Undo my changes
                </button>
              )}
              {!changed && <span className="text-xs text-muted">Change the text to save a new version.</span>}
            </div>
            {check && (
              <p role="status" className={`text-sm ${check.valid ? "text-good" : "text-bad"}`}>
                {check.valid ? "No mistakes found. This policy can be used." : `Problem: ${check.problem}`}
              </p>
            )}
            {message && (
              <p role={message.ok ? "status" : "alert"} className={`text-sm ${message.ok ? "text-good" : "text-bad"}`}>
                {message.text}
              </p>
            )}
          </div>
        )}
      </Card>

      <Card title="Version history">
        {history.error && <ErrorBox message={history.error} onRetry={history.reload} />}
        {!history.data ? (
          !history.error && <Loading />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-ink-2">
                <tr>
                  <th className="py-2 pr-3 font-medium">Version</th>
                  <th className="py-2 pr-3 font-medium">Saved</th>
                  <th className="py-2 pr-3 font-medium">By</th>
                  <th className="py-2 pr-3 font-medium">From</th>
                  <th className="py-2 font-medium">Checksum</th>
                </tr>
              </thead>
              <tbody>
                {history.data.map((item) => (
                  <tr key={item.version} className="border-t border-line">
                    <td className="py-2 pr-3">
                      {item.version}
                      {item.active && <span className="ml-2 text-xs font-medium text-good">in use</span>}
                    </td>
                    <td className="py-2 pr-3 whitespace-nowrap">{formatTime(item.created_at)}</td>
                    <td className="py-2 pr-3">{item.created_by}</td>
                    <td className="py-2 pr-3">{item.source}</td>
                    <td className="py-2 font-mono text-xs">{item.checksum.slice(0, 12)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
