# Developer Integrations

## Environment Contract

Use the same environment names across local apps, CI, containers, and Kubernetes:

```bash
OPENAI_BASE_URL=http://127.0.0.1:8081/v1
NANOMASK_BASE_URL=http://127.0.0.1:8081/v1
NANOMASK_ENTITIES_HEADER=X-NanoMask-Entities
```

`X-NanoMask-Entities` is the preferred per-request entity header. `X-ZPG-Entities` remains supported for older clients.

## Python and FastAPI

```python
from fastapi import FastAPI
from nanomask import OpenAI, with_entities

app = FastAPI()
client = OpenAI(api_key="replace-me")

@app.post("/summarize")
def summarize():
    return client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "Summarize Jane Smith's note"}],
        **with_entities(entities=["Jane Smith"]),
    )
```

## Flask

```python
from flask import Flask, jsonify
from nanomask import OpenAI, with_entities

app = Flask(__name__)
client = OpenAI(api_key="replace-me")

@app.post("/summarize")
def summarize():
    response = client.responses.create(
        model="gpt-4o-mini",
        input="Summarize Jane Smith's note",
        **with_entities(entities=["Jane Smith"]),
    )
    return jsonify(response.model_dump())
```

## Express

```js
import express from "express";
import OpenAI from "openai";
import { createClient, withEntities } from "@nanomask/openai";

const app = express();
const client = createClient({ OpenAIClass: OpenAI, apiKey: process.env.OPENAI_API_KEY });

app.post("/summarize", async (_req, res) => {
  const response = await client.chat.completions.create(
    {
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: "Summarize Jane Smith's note" }],
    },
    withEntities({}, ["Jane Smith"]),
  );
  res.json(response);
});
```

## Next.js Route Handler

```js
import OpenAI from "openai";
import { createClient, withEntities } from "@nanomask/openai";

const client = createClient({ OpenAIClass: OpenAI, apiKey: process.env.OPENAI_API_KEY });

export async function POST() {
  const response = await client.responses.create(
    { model: "gpt-4o-mini", input: "Summarize Jane Smith's note" },
    withEntities({}, ["Jane Smith"]),
  );
  return Response.json(response);
}
```

## LangChain

Point the OpenAI client used by LangChain at `OPENAI_BASE_URL=http://127.0.0.1:8081/v1`. For per-request entities, pass `X-NanoMask-Entities` through the model invocation headers or wrap the OpenAI client with the NanoMask SDK helper before constructing the chain.

## Verification

```bash
node tools/nanomask-doctor.mjs --base-url http://127.0.0.1:8081 --openai-smoke
node tools/nanomask-compat.mjs --base-url=http://127.0.0.1:8081/v1
```
