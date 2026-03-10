import os

from openai import OpenAI


client = OpenAI(
    base_url=os.environ.get("OPENAI_BASE_URL", "http://127.0.0.1:8081/v1"),
    api_key=os.environ.get("OPENAI_API_KEY", "replace-me"),
)

stream = client.chat.completions.create(
    model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
    stream=True,
    messages=[
        {
            "role": "user",
            "content": "Patient Jane Smith SSN 123-45-6789 needs follow up",
        }
    ],
)

for chunk in stream:
    delta = chunk.choices[0].delta.content or ""
    if delta:
        print(delta, end="", flush=True)

print()
