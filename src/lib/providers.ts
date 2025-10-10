import type { Message as ChatMessage } from "./ddb.js";
import { getSystemPrompt } from "./prompts.js";

type ProviderResult = { content: string; estimatedTokens: number };

const approxTokens = (s: string) => Math.max(1, Math.ceil((s || "").length / 4));
const mapMsgs = (msgs: ChatMessage[], systemMessage?: string) => {
  const messages = msgs.map(m => ({ role: m.role, content: m.content }));
  if (systemMessage) {
    messages.unshift({ role: "system", content: systemMessage });
  }
  return messages;
};

export async function runCompletion(
  provider: "OPENAI" | "DEEPSEEK", 
  model: string | undefined, 
  messages: ChatMessage[], 
  promptId?: string
): Promise<ProviderResult> {
  const text = messages.map(m => `${m.role}: ${m.content}`).join("\n");
  const promptToks = approxTokens(text);

  try {
    if (provider === "OPENAI" && process.env.OPENAI_API_KEY) {
      const mdl = model || process.env.OPENAI_MODEL || "gpt-4.1-nano";
      let systemMessage: string | undefined;
      let temperature = 0.2;
      
      if (promptId) {
        const prompt = await getSystemPrompt(promptId);
        systemMessage = prompt.system;
        temperature = prompt.temperature;
      }
      
      const r = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${process.env.OPENAI_API_KEY}` },
        body: JSON.stringify({ 
          model: mdl, 
          messages: mapMsgs(messages, systemMessage), 
          temperature 
        })
      });
      const data = await r.json();
      const content = data?.choices?.[0]?.message?.content ?? "";
      return { content, estimatedTokens: promptToks + approxTokens(content) };
    }
    if (provider === "DEEPSEEK" && process.env.DEEPSEEK_API_KEY) {
      const mdl = model || process.env.DEEPSEEK_MODEL || "deepseek-chat";
      const r = await fetch("https://api.deepseek.com/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${process.env.DEEPSEEK_API_KEY}` },
        body: JSON.stringify({ model: mdl, messages: mapMsgs(messages), temperature: 0.2 })
      });
      const data = await r.json();
      const content = data?.choices?.[0]?.message?.content ?? "";
      return { content, estimatedTokens: promptToks + approxTokens(content) };
    }
  } catch {}
  const mock = "[mocked completion]";
  return { content: mock, estimatedTokens: promptToks + approxTokens(mock) };
}