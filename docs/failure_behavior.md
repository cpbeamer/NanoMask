# Failure Behavior

| Situation | Developer-visible behavior | Operator signal |
|---|---|---|
| Upstream is unreachable | Request fails with `502` or `504` depending on connect/read phase. | `response_sent` includes timeout outcome and phase when applicable. |
| Request body exceeds `--max-body-size` | NanoMask returns `413 Payload Too Large`. | `body_too_large` warning. |
| Unsupported request content type | Default is `415 Unsupported Media Type`; can be changed to bypass. | `request_body_rejected` with body policy, content type, and encoding. |
| Unsupported response content type | Default is bypass unless a transform is required. | Response forwarding mode is logged. |
| Compressed upstream response requires restore | NanoMask rejects instead of transforming compressed bytes. | Body policy and response mode logs identify the decision. |
| Streaming response can pass through | SSE, NDJSON, and chunked responses are flushed incrementally. | `response_mode` indicates streamed forwarding. |
| JSON `HASH` restore is required | Response is buffered before restore. | `buffer_reason="json_unhash"`. |
| Entity file reload fails | Existing entity snapshot remains active. | `/readyz` reports entity reload health and reload failure metrics increase. |
| Admin API auth fails | Admin route returns `401` or `403`; proxy traffic is unaffected. | Admin denial is logged without sensitive token values. |
| Shutdown is in progress | `/readyz` returns `503`; in-flight requests drain until timeout. | Shutdown drain logs and metrics update. |
