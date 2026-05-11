import OpenAI from "openai";
import { createClient, withEntities } from "@nanomask/openai";

const client = createClient({
  OpenAIClass: OpenAI,
  apiKey: process.env.OPENAI_API_KEY ?? "replace-me",
});

const stream = await client.chat.completions.create(
  {
    model: process.env.OPENAI_MODEL ?? "gpt-4o-mini",
    stream: true,
    messages: [
      {
        role: "user",
        content: "Patient Jane Smith SSN 123-45-6789 needs follow up",
      },
    ],
  },
  withEntities({}, process.env.NANOMASK_ENTITIES ?? "Jane Smith"),
);

for await (const chunk of stream) {
  const delta = chunk.choices?.[0]?.delta?.content ?? "";
  if (delta) process.stdout.write(delta);
}

process.stdout.write("\n");
