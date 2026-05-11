#!/usr/bin/env node
const baseUrl = (process.argv.find((arg) => arg.startsWith("--base-url="))?.slice("--base-url=".length) ?? process.env.NANOMASK_BASE_URL ?? "http://127.0.0.1:8081/v1").replace(/\/$/, "");

async function assertCheck(name, fn) {
  await fn();
  console.log(`ok ${name}`);
}

await assertCheck("health endpoint reachable", async () => {
  const healthBase = baseUrl.replace(/\/v1$/, "");
  const res = await fetch(`${healthBase}/healthz`);
  if (res.status !== 200) throw new Error(`/healthz returned ${res.status}`);
});

await assertCheck("OpenAI chat path accepts entity header", async () => {
  const res = await fetch(`${baseUrl}/chat/completions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer nanomask-compat",
      "X-NanoMask-Entities": "Jane Smith",
    },
    body: JSON.stringify({
      model: "nanomask-compat",
      messages: [{ role: "user", content: "Jane Smith SSN 123-45-6789" }],
    }),
  });
  if (res.status >= 500) throw new Error(`expected non-5xx response, got ${res.status}`);
});

await assertCheck("OpenAI streaming path preserves SSE shape", async () => {
  const res = await fetch(`${baseUrl}/chat/completions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer nanomask-compat",
      "X-NanoMask-Entities": "Jane Smith",
    },
    body: JSON.stringify({
      model: "nanomask-compat",
      stream: true,
      messages: [{ role: "user", content: "Jane Smith streaming check" }],
    }),
  });
  if (res.status >= 500) throw new Error(`expected non-5xx response, got ${res.status}`);
  const contentType = res.headers.get("content-type") ?? "";
  if (res.status === 200 && !contentType.includes("text/event-stream")) {
    throw new Error(`expected text/event-stream for 200 response, got ${contentType}`);
  }
});
