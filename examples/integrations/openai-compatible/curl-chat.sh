#!/usr/bin/env sh
set -eu

: "${OPENAI_BASE_URL:=http://127.0.0.1:8081/v1}"
: "${OPENAI_API_KEY:=replace-me}"
: "${OPENAI_MODEL:=gpt-4o-mini}"

curl -N "${OPENAI_BASE_URL%/}/chat/completions" \
  -H "Authorization: Bearer ${OPENAI_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"${OPENAI_MODEL}\",\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"Patient Jane Smith SSN 123-45-6789 needs follow up\"}]}"
