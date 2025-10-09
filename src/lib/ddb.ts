import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";

let doc: DynamoDBDocumentClient | null = null;

export function ddb() {
  if (doc) return doc;
  const { AWS_REGION, DDB_ENDPOINT, LOCAL_DDB } = process.env;
  const client = new DynamoDBClient({
    region: AWS_REGION || "us-east-1",
    ...(LOCAL_DDB === "true" && DDB_ENDPOINT ? { endpoint: DDB_ENDPOINT, credentials: { accessKeyId: "local", secretAccessKey: "local" } } : {})
  });
  doc = DynamoDBDocumentClient.from(client, { marshallOptions: { removeUndefinedValues: true } });
  return doc;
}

export const TABLES = {
  Tokens: process.env.DDB_TOKENS || "Tokens",
  Users: process.env.DDB_USERS || "Users",
  Conversations: process.env.DDB_CONVERSATIONS || "Conversations",
  RateLimits: process.env.DDB_RATELIMITS || "RateLimits",
  TokenRequests: process.env.DDB_TOKENS_REQUEST || "TokenRequests"
};

export type TokenDoc = {
  token: string;
  user_id: string;
  provider: "OPENAI" | "DEEPSEEK" | "ANY";
  model?: string;
  limit: number;
  used: number;
  isActive: boolean;
  expiresAt?: string; // ISO
  createdAt: string;
  updatedAt: string;
};

export type UserDoc = {
  user_id: string;
  email?: string;
  name?: string;
  company?: string;
  createdAt: string;
  updatedAt: string;
};

export type Message = {
  role: "user" | "assistant" | "system";
  content: string;
  createdAt: string;
};

export type ConversationDoc = {
  conversation_id: string;
  token: string;
  user_id: string;
  displayName: string;
  token_user: string; // `${token}#${user_id}`
  createdAt: string;
  updatedAt: string;
  provider: "OPENAI" | "DEEPSEEK" | "ANY";
  messages: Message[];
};

// Optional: type for RateLimits table (handy for debugging)
export type RateLimitDoc = {
  key: string;      // "email:alice@example.com|/completions|28934736"
  count: number;    // incremented per request in window
  ttl: number;      // epoch seconds; DynamoDB TTL enabled on this attribute
};

export type TokenRequestDoc = {
  token: string;
  user_id: string;
  name: string;
  processed: boolean;
  createdAt: string;
  updatedAt: string;
  provider: "OPENAI" | "DEEPSEEK" | "ANY";
  limit: number;
  company?: string;
}