#!/usr/bin/env node
import { setTimeout as delay } from "node:timers/promises";

const args = new Map();
for (let i = 2; i < process.argv.length; i += 1) {
  const arg = process.argv[i];
  if (!arg.startsWith("--")) continue;
  const key = arg.slice(2);
  const next = process.argv[i + 1];
  if (next && !next.startsWith("--")) {
    args.set(key, next);
    i += 1;
  } else {
    args.set(key, "true");
  }
}

const baseUrl = (args.get("base-url") ?? process.env.NANOMASK_BASE_URL ?? "http://127.0.0.1:8081").replace(/\/v1\/?$/, "").replace(/\/$/, "");
const timeoutMs = Number(args.get("timeout-ms") ?? 3000);

async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function check(name, fn) {
  try {
    const detail = await fn();
    console.log(`ok   ${name}${detail ? ` - ${detail}` : ""}`);
    return true;
  } catch (error) {
    console.error(`fail ${name} - ${error.message}`);
    return false;
  }
}

const results = [];

results.push(await check("healthz", async () => {
  const res = await fetchWithTimeout(`${baseUrl}/healthz`, { headers: { Accept: "application/json" } });
  if (res.status !== 200) throw new Error(`expected 200, got ${res.status}`);
  const body = await res.json();
  return `version ${body.version ?? "unknown"}`;
}));

results.push(await check("readyz", async () => {
  const res = await fetchWithTimeout(`${baseUrl}/readyz`, { headers: { Accept: "application/json" } });
  if (res.status !== 200) throw new Error(`expected 200, got ${res.status}`);
  const body = await res.json();
  return body.shutdown ? `shutdown=${body.shutdown}` : "";
}));

results.push(await check("metrics", async () => {
  const res = await fetchWithTimeout(`${baseUrl}/metrics`);
  if (res.status !== 200) throw new Error(`expected 200, got ${res.status}`);
  const text = await res.text();
  if (!text.includes("nanomask_")) throw new Error("Prometheus body did not contain NanoMask series");
  return "Prometheus format available";
}));

if (args.get("openai-smoke") === "true") {
  results.push(await check("openai-compatible smoke", async () => {
    await delay(50);
    const res = await fetchWithTimeout(`${baseUrl}/v1/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer nanomask-doctor",
        "X-NanoMask-Entities": "Jane Smith",
      },
      body: JSON.stringify({
        model: args.get("model") ?? "nanomask-doctor",
        messages: [{ role: "user", content: "Hello from Jane Smith SSN 123-45-6789" }],
      }),
    });
    if (res.status >= 500) throw new Error(`upstream/proxy error ${res.status}`);
    return `status ${res.status}`;
  }));
}

if (results.some((ok) => !ok)) process.exit(1);
