import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { App } from "./App";
import { ADMIN_KEY, STATS, fakeGateway, timeline } from "./test/fakeGateway";

function signIn(key = ADMIN_KEY) {
  const user = userEvent.setup();
  render(<App />);
  return user.type(screen.getByLabelText("Admin API key"), key).then(async () => {
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    return user;
  });
}

describe("signing in", () => {
  it("opens the overview with a good admin key", async () => {
    fakeGateway({ "GET /v1/stats": { body: STATS }, "GET /v1/stats/timeline": { body: timeline() } });
    await signIn();
    expect(await screen.findByRole("heading", { name: "Overview" })).toBeInTheDocument();
  });

  it("says when the key is wrong", async () => {
    fakeGateway({
      "GET /v1/stats": { status: 401, body: { error: { code: "invalid_api_key", message: "x", request_id: "r" } } },
    });
    await signIn("lsg_wrong");
    expect(await screen.findByRole("alert")).toHaveTextContent("That key is not valid.");
  });

  it("says when the key is only a client key", async () => {
    fakeGateway({
      "GET /v1/stats": { status: 403, body: { error: { code: "forbidden", message: "x", request_id: "r" } } },
    });
    await signIn("lsg_client");
    expect(await screen.findByRole("alert")).toHaveTextContent("not an admin key");
  });

  it("keeps the key out of browser storage", async () => {
    fakeGateway({ "GET /v1/stats": { body: STATS }, "GET /v1/stats/timeline": { body: timeline() } });
    await signIn();
    await screen.findByRole("heading", { name: "Overview" });
    const stored = [JSON.stringify({ ...localStorage }), JSON.stringify({ ...sessionStorage }), document.cookie];
    for (const place of stored) expect(place).not.toContain(ADMIN_KEY);
  });

  it("forgets the key when logging out", async () => {
    const { sent } = fakeGateway({ "GET /v1/stats": { body: STATS }, "GET /v1/stats/timeline": { body: timeline() } });
    const user = await signIn();
    await screen.findByRole("heading", { name: "Overview" });
    await user.click(screen.getByRole("button", { name: "Log out" }));
    expect(screen.getByLabelText("Admin API key")).toHaveValue("");
    const before = sent.length;
    await user.click(screen.getByRole("button", { name: "Sign in" })); // disabled: empty key
    expect(sent.length).toBe(before);
  });
});
