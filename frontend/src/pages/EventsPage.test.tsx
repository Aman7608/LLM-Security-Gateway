import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { GatewayApi } from "../api";
import { ADMIN_KEY, auditEvent, fakeGateway } from "../test/fakeGateway";
import type { AuditEvent } from "../types";
import { EventsPage } from "./EventsPage";

const api = new GatewayApi(ADMIN_KEY);

function gateway(items: AuditEvent[], total = items.length, detail?: AuditEvent) {
  return fakeGateway({
    "GET /v1/events": { body: { total, limit: 25, offset: 0, items } },
    [`GET /v1/events/${(detail ?? items[0])?.request_id}`]: { body: detail ?? items[0] },
  });
}

describe("events", () => {
  it("lists events", async () => {
    gateway([auditEvent(), auditEvent({ request_id: "req-two", input_action: "block", risk_level: "critical" })]);
    render(<EventsPage api={api} />);
    expect(await screen.findByText("2 events")).toBeInTheDocument();
    const row = screen.getByRole("button", { name: "req-two" }).closest("tr")!;
    expect(row).toHaveTextContent("block");
    expect(row).toHaveTextContent("critical");
  });

  it("sends the filters and starts again at the first page", async () => {
    const { sent } = gateway([auditEvent()], 60);
    const user = userEvent.setup();
    render(<EventsPage api={api} />);
    await screen.findByText("60 events");
    await user.click(screen.getByRole("button", { name: "Older" }));
    expect(sent.at(-1)?.query.get("offset")).toBe("25");

    await user.selectOptions(screen.getByLabelText("Risk"), "high");
    await user.type(screen.getByLabelText("Finding type"), "EMAIL_ADDRESS");
    await user.click(screen.getByRole("button", { name: "Search" }));
    const last = Object.fromEntries(sent.at(-1)!.query);
    expect(last).toEqual({ min_risk: "high", finding_type: "EMAIL_ADDRESS", limit: "25", offset: "0" });
  });

  it("cannot page past the ends", async () => {
    gateway([auditEvent()], 1);
    render(<EventsPage api={api} />);
    await screen.findByText("1 events");
    expect(screen.getByRole("button", { name: "Newer" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Older" })).toBeDisabled();
  });

  it("opens an event with its findings", async () => {
    gateway([auditEvent()]);
    const user = userEvent.setup();
    render(<EventsPage api={api} />);
    await user.click(await screen.findByRole("button", { name: "req-abc123" }));
    const detail = (await screen.findByRole("heading", { name: "Findings" })).closest("section")!;
    expect(within(detail).getByText("EMAIL_ADDRESS")).toBeInTheDocument();
    expect(within(detail).getByText("fp_0123456789abcdef")).toBeInTheDocument();
    expect(within(detail).getByText("messages[0]")).toBeInTheDocument();
  });

  it("shows a saved prompt as plain text, never as HTML", async () => {
    const attack = '<img src=x onerror="alert(1)"><script>alert(2)</script>';
    const event = auditEvent({ redacted_prompt: `Hi ${attack}` });
    gateway([event]);
    const user = userEvent.setup();
    const { container } = render(<EventsPage api={api} />);
    await user.click(await screen.findByRole("button", { name: "req-abc123" }));
    expect(await screen.findByText(`Hi ${attack}`)).toBeInTheDocument();
    expect(container.querySelector("img, script")).toBeNull();
  });

  it("says when nothing matches", async () => {
    gateway([]);
    render(<EventsPage api={api} />);
    expect(await screen.findByText("No events match these filters.")).toBeInTheDocument();
  });
});
