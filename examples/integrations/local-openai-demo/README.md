# Local OpenAI-Compatible Demo

This demo starts NanoMask in front of a local mock OpenAI-compatible upstream. It does not need a vendor API key.

```bash
docker compose -f examples/integrations/local-openai-demo/docker-compose.yaml up --build
```

In another terminal:

```bash
curl -s http://127.0.0.1:8081/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer demo' \
  -H 'X-NanoMask-Entities: Jane Smith' \
  -d '{"model":"demo","messages":[{"role":"user","content":"Summarize Jane Smith SSN 123-45-6789"}]}'
```

The mock upstream replies with `Entity_A`; NanoMask restores that alias to `Jane Smith` on the way back to the client.

Run the bundled smoke check:

```bash
docker compose -f examples/integrations/local-openai-demo/docker-compose.yaml --profile smoke up --build --abort-on-container-exit
```
