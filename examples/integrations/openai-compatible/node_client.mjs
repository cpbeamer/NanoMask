import OpenAI from "openai";

const client = new OpenAI({
  baseURL: process.env.OPENAI_BASE_URL ?? "http://127.0.0.1:8081/v1",
  apiKey: process.env.OPENAI_API_KEY ?? "replace-me",
});

const stream = await client.chat.completions.create({
  model: process.env.OPENAI_MODEL ?? "gpt-4o-mini",
  stream: true,
  messages: [
    {
      role: "user",
      content: "Patient Jane Smith SSN 123-45-6789 needs follow up",
    },
  ],
});

for await (const chunk of stream) {
  const delta = chunk.choices?.[0]?.delta?.content ?? "";
  if (delta) process.stdout.write(delta);
}

process.stdout.write("\n");
