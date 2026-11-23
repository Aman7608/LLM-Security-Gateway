import { useState, type FormEvent } from "react";
import { ApiError, GatewayApi, describeError } from "../api";

interface Props {
  onLogin: (key: string) => void;
}

export function LoginPage({ onLogin }: Props) {
  const [key, setKey] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    const trimmed = key.trim();
    if (!trimmed) return;
    setChecking(true);
    setProblem(null);
    try {
      // Any admin route works to test the key; stats is small
      await new GatewayApi(trimmed).stats();
      onLogin(trimmed);
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        setProblem("That key is not valid.");
      } else if (error instanceof ApiError && error.status === 403) {
        setProblem("That key works, but it is not an admin key.");
      } else {
        setProblem(describeError(error));
      }
    } finally {
      setChecking(false);
    }
  }

  return (
    <main className="mx-auto mt-24 max-w-md px-4">
      <form onSubmit={submit} className="rounded-lg border border-line bg-surface p-6">
        <h1 className="text-lg font-semibold">LLM Security Gateway</h1>
        <p className="mt-1 text-sm text-ink-2">Sign in with an admin API key.</p>
        <label htmlFor="api-key" className="mt-5 block text-sm font-medium">
          Admin API key
        </label>
        <input
          id="api-key"
          type="password"
          autoComplete="off"
          spellCheck={false}
          value={key}
          onChange={(event) => setKey(event.target.value)}
          className="mt-1 w-full rounded border border-axis bg-page px-3 py-2 text-sm"
          placeholder="lsg_..."
        />
        {problem && (
          <p role="alert" className="mt-3 text-sm text-bad">
            {problem}
          </p>
        )}
        <button
          type="submit"
          disabled={checking || !key.trim()}
          className="mt-5 w-full rounded bg-accent px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
        >
          {checking ? "Checking..." : "Sign in"}
        </button>
        <p className="mt-4 text-xs text-muted">
          Make a key with <code>scripts/manage_keys.py create dashboard --role admin</code>. The key is kept only
          in this tab and is forgotten when you reload or log out.
        </p>
      </form>
    </main>
  );
}
