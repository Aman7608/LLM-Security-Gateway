import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { GatewayApi } from "../api";
import { niceMax } from "../components/RiskChart";
import { ADMIN_KEY, STATS, fakeGateway, timeline } from "../test/fakeGateway";
import { OverviewPage } from "./OverviewPage";

const api = new GatewayApi(ADMIN_KEY);

function tile(label: string) {
  return screen.getByText(label, { selector: "dt" }).parentElement!;
}

describe("overview", () => {
  it("shows the headline numbers", async () => {
    fakeGateway({ "GET /v1/stats": { body: STATS }, "GET /v1/stats/timeline": { body: timeline() } });
    render(<OverviewPage api={api} />);
    await screen.findByText("Requests");
    expect(tile("Requests")).toHaveTextContent("120");
    expect(tile("Blocked")).toHaveTextContent("15"); // 12 prompts + 3 answers
    expect(tile("Prompt injection")).toHaveTextContent("9");
    expect(tile("Personal data")).toHaveTextContent("22");
    expect(tile("Secrets")).toHaveTextContent("4");
  });

  it("asks for the chosen period", async () => {
    const { sent } = fakeGateway({ "GET /v1/stats": { body: STATS }, "GET /v1/stats/timeline": { body: timeline() } });
    const user = userEvent.setup();
    render(<OverviewPage api={api} />);
    await screen.findByText("Requests");
    await user.selectOptions(screen.getByLabelText("Period"), "Last 7 days");
    const last = sent.filter((r) => r.path === "/v1/stats/timeline").at(-1)!;
    expect(Object.fromEntries(last.query)).toEqual({ hours: "168", step: "day" });
    const stats = sent.filter((r) => r.path === "/v1/stats").at(-1)!;
    expect(stats.query.get("since")).toMatch(/Z$/); // always with a timezone
  });

  it("warns when audit records could not be saved", async () => {
    fakeGateway({
      "GET /v1/stats": { body: { ...STATS, failed_writes: 2 } },
      "GET /v1/stats/timeline": { body: timeline() },
    });
    render(<OverviewPage api={api} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("2 audit records could not be saved");
  });

  it("shows the counts of one bar on hover", async () => {
    fakeGateway({ "GET /v1/stats": { body: STATS }, "GET /v1/stats/timeline": { body: timeline() } });
    const user = userEvent.setup();
    render(<OverviewPage api={api} />);
    const bars = await screen.findAllByTestId("bar-target");
    expect(bars).toHaveLength(3);
    await user.hover(bars[2]!);
    const tip = screen.getByRole("status");
    expect(within(tip).getByText("critical").parentElement).toHaveTextContent("1");
    expect(tip).toHaveTextContent(/total\s*6/);
  });

  it("can show the chart as a table", async () => {
    fakeGateway({ "GET /v1/stats": { body: STATS }, "GET /v1/stats/timeline": { body: timeline() } });
    const user = userEvent.setup();
    render(<OverviewPage api={api} />);
    await user.click(await screen.findByRole("button", { name: "Show as table" }));
    const rows = screen.getAllByRole("row");
    expect(rows).toHaveLength(4); // heading + 3 time steps
    expect(rows[3]).toHaveTextContent("302016"); // none 3, low 0, medium 2, high 0, critical 1, total 6
  });

  it("shows an error with a way to try again", async () => {
    fakeGateway({
      "GET /v1/stats": { status: 503, body: { error: { code: "unavailable", message: "Down.", request_id: "r1" } } },
      "GET /v1/stats/timeline": { body: timeline() },
    });
    render(<OverviewPage api={api} />);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Down. (reference r1)");
    expect(within(alert).getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });
});

describe("niceMax", () => {
  it.each([
    [0, 1],
    [1, 1],
    [3, 5],
    [7, 10],
    [12, 20],
    [101, 200],
    [500, 500],
  ])("rounds %i up to %i", (value, expected) => {
    expect(niceMax(value)).toBe(expected);
  });
});
