import { describe, expect, it } from "vitest";
import { apiURL } from "./api";

describe("apiURL", () => {
  it("builds an absolute API URL", () => {
    expect(apiURL("/health/live")).toBe("http://localhost:8080/health/live");
  });

  it("rejects paths without a leading slash", () => {
    expect(() => apiURL("health/live")).toThrow("API path must start with /");
  });
});
