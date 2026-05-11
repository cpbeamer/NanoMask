import http from "node:http";

const port = Number(process.env.PORT ?? 8080);

function sendJson(res, status, body, headers = {}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
    ...headers,
  });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function extractText(payload) {
  if (typeof payload.input === "string") return payload.input;
  if (Array.isArray(payload.messages)) {
    return payload.messages.map((message) => message.content ?? "").join(" ");
  }
  return JSON.stringify(payload);
}

const server = http.createServer(async (req, res) => {
  if (req.url === "/healthz" || req.url === "/readyz") {
    sendJson(res, 200, { status: "ok" });
    return;
  }

  if (req.method !== "POST") {
    sendJson(res, 404, { error: "not found" });
    return;
  }

  const raw = await readBody(req);
  const payload = raw ? JSON.parse(raw) : {};
  const text = extractText(payload);
  const responseText = `Mock upstream saw: ${text}. Reply mentions Entity_A for restore testing.`;

  if (payload.stream === true) {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    });
    res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: responseText } }] })}\n\n`);
    res.write("data: [DONE]\n\n");
    res.end();
    return;
  }

  sendJson(res, 200, {
    id: "chatcmpl-nanomask-demo",
    object: "chat.completion",
    choices: [
      {
        index: 0,
        message: { role: "assistant", content: responseText },
        finish_reason: "stop",
      },
    ],
  });
});

server.listen(port, "0.0.0.0", () => {
  console.log(`mock OpenAI-compatible upstream listening on ${port}`);
});
