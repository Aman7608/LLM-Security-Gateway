import { useMemo, useState } from "react";
import { GatewayApi } from "./api";
import { EventsPage } from "./pages/EventsPage";
import { LoginPage } from "./pages/LoginPage";
import { OverviewPage } from "./pages/OverviewPage";
import { PolicyPage } from "./pages/PolicyPage";

const PAGES = [
  { id: "overview", label: "Overview" },
  { id: "events", label: "Events" },
  { id: "policy", label: "Policy" },
] as const;
type PageId = (typeof PAGES)[number]["id"];

export function App() {
  // The admin key lives only here, in memory. Reloading the page forgets it.
  const [key, setKey] = useState<string | null>(null);
  const [page, setPage] = useState<PageId>("overview");
  const api = useMemo(() => (key ? new GatewayApi(key) : null), [key]);

  if (!api) return <LoginPage onLogin={setKey} />;

  return (
    <div className="min-h-screen">
      <header className="border-b border-line bg-surface">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3">
          <h1 className="text-base font-semibold">LLM Security Gateway</h1>
          <nav aria-label="Pages" className="flex gap-1">
            {PAGES.map((item) => (
              <button
                key={item.id}
                type="button"
                aria-current={page === item.id ? "page" : undefined}
                onClick={() => setPage(item.id)}
                className={`rounded px-3 py-1.5 text-sm ${
                  page === item.id ? "bg-accent/15 font-medium text-ink" : "text-ink-2 hover:bg-line/60"
                }`}
              >
                {item.label}
              </button>
            ))}
          </nav>
          <button
            type="button"
            onClick={() => {
              setKey(null);
              setPage("overview");
            }}
            className="ml-auto rounded px-3 py-1.5 text-sm text-ink-2 hover:bg-line/60"
          >
            Log out
          </button>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-4 py-6">
        {page === "overview" && <OverviewPage api={api} />}
        {page === "events" && <EventsPage api={api} />}
        {page === "policy" && <PolicyPage api={api} />}
      </main>
    </div>
  );
}
