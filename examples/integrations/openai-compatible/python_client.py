import os

from nanomask import OpenAI, with_entities


client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", "replace-me"))

stream = client.chat.completions.create(
    model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
    stream=True,
    messages=[
        {
            "role": "user",
            "content": "Patient Jane Smith SSN 123-45-6789 needs follow up",
        }
    ],
    **with_entities(entities=os.environ.get("NANOMASK_ENTITIES", "Jane Smith")),
)

for chunk in stream:
    delta = chunk.choices[0].delta.content or ""
    if delta:
        print(delta, end="", flush=True)

print()
