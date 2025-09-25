import { readFile } from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

interface SystemPrompt {
  id: string;
  description: string;
  system: string;
  temperature: number;
  maxTokens: number;
}

interface PromptsConfig {
  prompts: {
    [key: string]: SystemPrompt;
  };
}

let promptsCache: PromptsConfig | null = null;

export async function loadPrompts(): Promise<PromptsConfig> {
  if (promptsCache) return promptsCache;
  
  const promptsPath = path.join(__dirname, '..', 'config', 'prompts.json');
  const content = await readFile(promptsPath, 'utf-8');
  promptsCache = JSON.parse(content);
  return promptsCache as PromptsConfig;
}

export async function getSystemPrompt(promptId: string): Promise<SystemPrompt> {
  const config = await loadPrompts();
  const prompt = config.prompts[promptId];
  
  if (!prompt) {
    throw new Error(`PROMPT_NOT_FOUND: System prompt '${promptId}' not found`);
  }
  
  return prompt;
}

export async function listPrompts(): Promise<{ id: string; description: string }[]> {
  const config = await loadPrompts();
  return Object.values(config.prompts).map(({ id, description }) => ({
    id,
    description
  }));
}
