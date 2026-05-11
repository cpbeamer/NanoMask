import assert from "node:assert/strict";
import test from "node:test";

import {
  createClient,
  entityHeaders,
  healthcheckUrl,
  normalizeBaseUrl,
  verify,
  withEntities,
} from "../src/index.js";

class FakeClient {
  constructor(options) {
    this.options = options;
  }
}

test("normalizeBaseUrl adds /v1", () => {
  assert.equal(normalizeBaseUrl("http://127.0.0.1:8081"), "http://127.0.0.1:8081/v1");
});

test("healthcheckUrl strips /v1", () => {
  assert.equal(healthcheckUrl("http://127.0.0.1:8081/v1"), "http://127.0.0.1:8081/healthz");
});

test("entityHeaders joins names", () => {
  assert.deepEqual(entityHeaders(["Jane Doe", "ACME"]), {
    "X-NanoMask-Entities": "Jane Doe, ACME",
  });
});

test("createClient injects NanoMask transport defaults", () => {
  const client = createClient({
    OpenAIClass: FakeClient,
    apiKey: "replace-me",
    entities: ["Jane Doe"],
    defaultHeaders: { "x-trace-id": "abc" },
  });

  assert.equal(client.options.baseURL, "http://127.0.0.1:8081/v1");
  assert.equal(client.options.defaultHeaders["x-trace-id"], "abc");
  assert.equal(client.options.defaultHeaders["X-NanoMask-Entities"], "Jane Doe");
});

test("withEntities builds per-request extraHeaders", () => {
  const options = withEntities({ extraHeaders: { "x-trace-id": "abc" } }, ["Jane Doe"]);
  assert.equal(options.extraHeaders["x-trace-id"], "abc");
  assert.equal(options.extraHeaders["X-NanoMask-Entities"], "Jane Doe");
});

test("verify reports status from fetch", async () => {
  const result = await verify({
    fetchImpl: async () => ({ status: 200 }),
  });

  assert.equal(result.ok, true);
  assert.equal(result.status, 200);
});
