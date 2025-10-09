import { generateToken } from "../utils/utils.js";
import { ddb, TABLES, TokenDoc, TokenRequestDoc } from "./ddb.js";
import { GetCommand, UpdateCommand, ScanCommand, PutCommand, DeleteCommand } from "@aws-sdk/lib-dynamodb";
import { createUserIfNotExists, getUserById } from "./users.js";

export interface TokenDocReq {
  user_id: string;
  provider: "OPENAI" | "DEEPSEEK" | "ANY";
  limit: number;
  used?: number;
  isActive?: boolean;
  expiresAt?: string;
  createdAt?: string;
  updatedAt?: string;
}

export async function loadActiveToken(tokenStr: string): Promise<TokenDoc> {
  const db = ddb();
  const out = await db.send(new GetCommand({ TableName: TABLES.Tokens, Key: { token: tokenStr } }));
  const t = out.Item as TokenDoc | undefined;
  if (!t) throw new Error("TOKEN_NOT_FOUND");
  if (!t.isActive) throw new Error("TOKEN_INACTIVE");
  if (t.expiresAt && new Date(t.expiresAt) < new Date()) throw new Error("TOKEN_EXPIRED");
  return t;
}

export async function loadTokenRequest(tokenStr: string): Promise<TokenRequestDoc | null> {
  const db = ddb();
  const out = await db.send(new GetCommand({ TableName: TABLES.TokenRequests, Key: { token: tokenStr } }));
  return out.Item as TokenRequestDoc || null;
}

export async function incrementTokenUsed(tokenStr: string, amount: number) {
  const db = ddb();
  await db.send(new UpdateCommand({
    TableName: TABLES.Tokens,
    Key: { token: tokenStr },
    UpdateExpression: "SET #u = if_not_exists(#u, :z) + :a, #upd = :now",
    ExpressionAttributeNames: { "#u": "used", "#upd": "updatedAt" },
    ExpressionAttributeValues: { ":a": amount, ":z": 0, ":now": new Date().toISOString() }
  }));
}

export async function listUnprocessedTokensRequest(): Promise<TokenRequestDoc[]> {
  const result = await ddb().send(new ScanCommand({
    TableName: TABLES.TokenRequests,
    FilterExpression: '#processed = :processed',
    ExpressionAttributeNames: {
      '#processed': 'processed'
    },
    ExpressionAttributeValues: {
      ':processed': false
    }
  }));
  
  return result.Items as TokenRequestDoc[];
}

export async function listTokens(email: string = '', limit: number = 100): Promise<TokenDoc[]> {
  const db = ddb();
  if (email !== '') {
    const out = await db.send(new ScanCommand({ TableName: TABLES.Tokens, FilterExpression: "user_id = :uid", ExpressionAttributeValues: { ":uid": email }, Limit: limit }));
    return (out.Items as TokenDoc[]) || [];
  }
  const out = await db.send(new ScanCommand({ TableName: TABLES.Tokens, Limit: limit }));
  return (out.Items as TokenDoc[]) || [];
}

export async function createTokenRequestMaxThreeTokens(email: string, name: string, provider: "OPENAI" | "DEEPSEEK" | "ANY", limit: number, company: string = ''): Promise<TokenRequestDoc> {
  const existingTokens = await listTokens(email, 10);
  if (existingTokens.length >= 3) {
    throw new Error("TOKEN_LIMIT_REACHED: A maximum of 3 active tokens are allowed per user.");
  }
  return createTokenRequest(email, name, provider, limit, company);
}

export async function createTokenRequest(email: string, name: string, provider: "OPENAI" | "DEEPSEEK" | "ANY", limit: number, company: string = ''): Promise<TokenRequestDoc> {
  const db = ddb();
  const now = new Date().toISOString();
  const token = generateToken(email);
  const req: TokenRequestDoc = {
    token,
    name,
    user_id: email,
    provider,
    limit,
    company,
    processed: false,
    createdAt: now,
    updatedAt: now
  };
  await db.send(new PutCommand({ TableName: TABLES.TokenRequests, Item: req }));
  return req;
}

export async function createTokenIfNotExists(tokenReq: TokenDocReq): Promise<TokenDoc | null> {
  const db = ddb();
  const now = new Date().toISOString();
  const token = generateToken(tokenReq.user_id);
  const tokenDoc: TokenDoc = {
    token,
    user_id: tokenReq.user_id,
    provider: tokenReq.provider,
    limit: tokenReq.limit,
    used: tokenReq.used || 0,
    isActive: tokenReq.isActive !== undefined ? tokenReq.isActive : true,
    createdAt: tokenReq.createdAt || now,
    expiresAt: tokenReq.expiresAt,
    updatedAt: tokenReq.updatedAt || now
  };
  try {
    await db.send(new PutCommand({
      TableName: TABLES.Tokens,
      Item: tokenDoc,
      ConditionExpression: "attribute_not_exists(#tk)",
      ExpressionAttributeNames: {
        "#tk": "token"
      }
    }));
    return tokenDoc;
  } catch (e) {
    console.log('Error creating token (might already exist):', e);
    return null; // Token already exists
  }
}

export async function transformTokenRequestToToken(token: string): Promise<TokenDoc> {
  const db = ddb();
  const now = new Date().toISOString();
  
  if (!token || token.length < 10) {
    throw new Error("INVALID_TOKEN_REQUEST_ID");
  }
  
  const req = await loadTokenRequest(token);
  if (!req) {
    throw new Error("TOKEN_REQUEST_NOT_FOUND");
  }
  if (req.processed) {
    throw new Error("TOKEN_REQUEST_ALREADY_PROCESSED");
  }
  
  // Ensure user exists
  
  const user = await getUserById(req.user_id);
  if (!user) await createUserIfNotExists(req.user_id, req.name, req.user_id, req.company || '');
  
  const tokenDoc: TokenDoc = {
    token: req.token,
    user_id: req.user_id,
    provider: req.provider,
    limit: req.limit,
    used: 0,
    isActive: true,
    createdAt: now,
    updatedAt: now
  };
  
  // Use PutCommand instead of UpdateCommand for creating new tokens
  await db.send(new PutCommand({
    TableName: TABLES.Tokens,
    Item: tokenDoc,
    ConditionExpression: "attribute_not_exists(#tk)",
    ExpressionAttributeNames: {
      "#tk": "token"
    }
  }));
  
  // Mark the token request as processed
  try {
    await db.send(new UpdateCommand({
      TableName: TABLES.TokenRequests,
      Key: { token: req.token },
      UpdateExpression: "SET #processed = :processed, updatedAt = :updatedAt",
      ExpressionAttributeNames: {
        "#processed": "processed"
      },
      ExpressionAttributeValues: {
        ":processed": true,
        ":updatedAt": now
      }
    }));
  } catch (error) {
    console.log('Error marking token request as processed:', error);
    // Continue execution even if this fails
  }
  
  return tokenDoc;
}

export async function updateToken(tokenStr: string, updates: Partial<Omit<TokenDoc, 'token' | 'user_id' | 'createdAt'>>): Promise<boolean> {
  const db = ddb();
  const updateExpr: string[] = [];
  const exprAttrNames: Record<string, string> = {};
  const exprAttrValues: Record<string, any> = {};
  if (updates.provider) {
    updateExpr.push("provider = :prov");
    exprAttrValues[":prov"] = updates.provider;
  }
  if (updates.limit !== undefined) {
    updateExpr.push("#l = :lim");
    exprAttrNames["#l"] = "limit";
    exprAttrValues[":lim"] = updates.limit;
  }
  if (updates.used !== undefined) {
    updateExpr.push("used = :used");
    exprAttrValues[":used"] = updates.used;
  }
  if (updates.isActive !== undefined) {
    updateExpr.push("isActive = :ia");
    exprAttrValues[":ia"] = updates.isActive;
  }
  if (updates.expiresAt !== undefined) {
    updateExpr.push("expiresAt = :exp");
    exprAttrValues[":exp"] = updates.expiresAt;
  }
  if (updateExpr.length === 0) return false; // Nothing to update
  updateExpr.push("updatedAt = :ua");
  exprAttrValues[":ua"] = new Date().toISOString();
  try {
    await db.send(new UpdateCommand({
      TableName: TABLES.Tokens,
      Key: { token: tokenStr },
      UpdateExpression: "SET " + updateExpr.join(", "),
      ExpressionAttributeValues: exprAttrValues,
      ConditionExpression: "attribute_exists(#tk)",
      ExpressionAttributeNames: {
        ...exprAttrNames,
        "#tk": "token"
      }
    }));
    return true;
  } catch (e) {
    return false;
  }
}

export async function toggleTokenActive(tokenStr: string, isActive: boolean): Promise<boolean> {
  const db = ddb();
  try {
    await db.send(new UpdateCommand({
      TableName: TABLES.Tokens,
      Key: { token: tokenStr },
      UpdateExpression: "SET isActive = :ia, updatedAt = :ua",
      ExpressionAttributeValues: {
        ":ia": isActive,
        ":ua": new Date().toISOString()
      },
      ConditionExpression: "attribute_exists(#tk)",
      ExpressionAttributeNames: {
        "#tk": "token"
      }
    }));
    return true;
  } catch (e) {
    return false;
  }
}

export async function deleteToken(tokenStr: string): Promise<boolean> {
  const db = ddb();
  try {
    await db.send(new DeleteCommand({
      TableName: TABLES.Tokens,
      Key: { token: tokenStr }
    }));
    return true;
  } catch (e) {
    return false;
  }
}