import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { GatewayApi } from "../api";
import { ADMIN_KEY, POLICY_TEXT, fakeGateway } from "../test/fakeGateway";
import { PolicyPage } from "./PolicyPage";

const api = new GatewayApi(ADMIN_KEY);

const ACTIVE = {
  version: 1,
  checksum: "abc123def4567890",
  created_by: "file",
  source: "file",
  created_at: "2026-11-20T10:00:00Z",
  text: POLICY_TEXT,
};
const HISTORY = [{ ...ACTIVE, active: true }];

function gateway(extra: Parameters<typeof fakeGateway>[0] = {}) {
  return fakeGateway({
    "GET /v1/policies/active": { body: ACTIVE },
    "GET /v1/policies/history": { body: HISTORY },
    ...extra,
  });
}

async function openEditor() {
  const user = userEvent.setup();
  render(<PolicyPage api={api} />);
  const editor = await screen.findByLabelText("Policy (YAML)");
  return { user, editor };
}

describe("policy", () => {
  it("shows the active policy and its history", async () => {
    gateway();
    const { editor } = await openEditor();
    expect(editor).toHaveValue(POLICY_TEXT);
    expect(screen.getByText("Active policy: version 1")).toBeInTheDocument();
    expect(screen.getByText("in use")).toBeInTheDocument();
  });

  it("can only save after a change", async () => {
    gateway();
    const { user, editor } = await openEditor();
    expect(screen.getByRole("button", { name: "Save and use" })).toBeDisabled();
    await user.type(editor, "# note");
    expect(screen.getByRole("button", { name: "Save and use" })).toBeEnabled();
    await user.click(screen.getByRole("button", { name: "Undo my changes" }));
    expect(editor).toHaveValue(POLICY_TEXT);
  });

  it("shows the problem in a broken policy", async () => {
    gateway({ "POST /v1/policies/validate": { body: { valid: false, problem: "rules: must be a list" } } });
    const { user } = await openEditor();
    await user.click(screen.getByRole("button", { name: "Check for mistakes" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Problem: rules: must be a list");
  });

  it("saves only after the admin confirms", async () => {
    const { sent } = gateway({
      "PUT /v1/policies/active": (request) => ({
        body: { ...ACTIVE, version: 2, text: (request.body as { policy: string }).policy },
      }),
    });
    const confirm = vi.spyOn(window, "confirm").mockReturnValueOnce(false).mockReturnValueOnce(true);
    const { user, editor } = await openEditor();
    await user.type(editor, "# note");

    await user.click(screen.getByRole("button", { name: "Save and use" }));
    expect(sent.some((r) => r.method === "PUT")).toBe(false); // said no

    await user.click(screen.getByRole("button", { name: "Save and use" }));
    expect(await screen.findByText("Saved. Policy version 2 is now in use.")).toBeInTheDocument();
    expect(sent.find((r) => r.method === "PUT")?.body).toEqual({ policy: `${POLICY_TEXT}# note` });
    expect(confirm).toHaveBeenCalledTimes(2);
  });

  it("shows why a save was refused", async () => {
    gateway({
      "PUT /v1/policies/active": {
        status: 422,
        body: { error: { code: "invalid_policy", message: "Unknown action 'nuke'.", request_id: "req-7" } },
      },
    });
    vi.spyOn(window, "confirm").mockReturnValue(true);
    const { user, editor } = await openEditor();
    await user.type(editor, "x");
    await user.click(screen.getByRole("button", { name: "Save and use" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Unknown action 'nuke'. (reference req-7)");
  });
});
