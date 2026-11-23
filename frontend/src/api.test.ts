import { describe, expect, it, vi } from "vitest";
import { ApiError, GatewayApi, describeError } from "./api";
import { ADMIN_KEY, STATS, fakeGateway } from "./test/fakeGateway";

describe("GatewayApi", () => {
  it("sends the key in a header and never uses cookies", async () => {
    const { sent } = fakeGateway({ "GET /v1/stats": { body: STATS } });
    await new GatewayApi(ADMIN_KEY).stats();
    expect(sent[0]?.headers["X-API-Key"]).toBe(ADMIN_KEY);
    expect(sent[0]?.credentials).toBe("omit");
  });

  it("leaves empty filters out of the address", async () => {
    const { sent } = fakeGateway({ "GET /v1/events": { body: { total: 0, limit: 25, offset: 0, items: [] } } });
    await new GatewayApi(ADMIN_KEY).events({ min_risk: "high", action: "", status: undefined, limit: 25 });
    expect(Object.fromEntries(sent[0]!.query)).toEqual({ min_risk: "high", limit: "25" });
  });

  it("sends policies as JSON", async () => {
    const { sent } = fakeGateway({ "POST /v1/policies/validate": { body: { valid: true, problem: null } } });
    await new GatewayApi(ADMIN_KEY).validatePolicy("version: 1");
    expect(sent[0]?.body).toEqual({ policy: "version: 1" });
    expect(sent[0]?.headers["Content-Type"]).toBe("application/json");
  });

  it("encodes the event id in the address", async () => {
    const { sent } = fakeGateway({});
    await new GatewayApi(ADMIN_KEY).event("a/b?c").catch(() => undefined);
    expect(sent[0]?.path).toBe("/v1/events/a%2Fb%3Fc");
  });

  it("turns the gateway's error format into an ApiError", async () => {
    fakeGateway({
      "GET /v1/stats": {
        status: 403,
        body: { error: { code: "forbidden", message: "Admins only.", request_id: "req-9" } },
      },
    });
    const error = await new GatewayApi(ADMIN_KEY).stats().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 403, code: "forbidden", requestId: "req-9" });
    expect(describeError(error)).toBe("Admins only. (reference req-9)");
  });

  it("explains when the gateway cannot be reached", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    const error = await new GatewayApi(ADMIN_KEY).stats().catch((e: unknown) => e);
    expect(error).toMatchObject({ status: 0, code: "network_error" });
    expect(describeError(error)).toContain("Is it running?");
  });

  it("copes with an error that is not JSON", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("Bad Gateway", { status: 502 })));
    const error = await new GatewayApi(ADMIN_KEY).stats().catch((e: unknown) => e);
    expect(error).toMatchObject({ status: 502, code: "unknown_error" });
  });
});
