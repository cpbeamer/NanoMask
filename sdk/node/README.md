# `@nanomask/openai`

Thin Node helpers for routing official OpenAI SDK traffic through NanoMask.

## Install

```bash
npm install openai ./sdk/node
```

## Usage

```js
import OpenAI from "openai";
import { createClient, verify } from "@nanomask/openai";

const client = createClient({
  OpenAIClass: OpenAI,
  apiKey: process.env.OPENAI_API_KEY,
  entities: ["Jane Doe", "ACME Health"],
});

const probe = await verify();
if (!probe.ok) throw new Error(probe.error ?? "NanoMask probe failed");
```

## What it does

- defaults `baseUrl` to `http://127.0.0.1:8081/v1`
- injects `X-ZPG-Entities` when `entities` is provided
- exposes `verify()` for CI and readiness checks

The wrapper is intentionally thin. It delegates transport and request behavior to the official `openai` client you already use.
