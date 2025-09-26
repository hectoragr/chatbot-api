import type { VercelRequest, VercelResponse } from "@vercel/node";
import express, { Request as ExpressRequest, NextFunction, Response } from "express";
import { auth as jwtCheck } from 'express-oauth2-jwt-bearer';

type Request = ExpressRequest & {
  query: any;
  body: any;
  params: any;
  headers: {
    [key: string]: string | string[] | undefined;
    authorization?: string;
  };
  auth?: {
    payload?: {
      [key: string]: any;
    };
    userInfo?: {
      email: string;
      [key: string]: any;
    };
  };
};
import cors from 'cors';
import * as dotenv from 'dotenv';
dotenv.config();

import { requireAdmin, authRouter, requireAuth, getUserProfile } from "../src/lib/auth.js";
import { ddb, TABLES, Message } from "../src/lib/ddb.js";
import { loadActiveToken, incrementTokenUsed } from "../src/lib/tokens.js";
import { listPrompts } from "../src/lib/prompts.js";
import { ensureConversation, getConversation, getLatestConversationByTokenUser, getConversationsByTokenUser, appendMessages, deleteByTokenAndUser, runSmallModelForSummary, renameConversation } from "../src/lib/conversations.js";
import { runCompletion } from "../src/lib/providers.js";
import { PutCommand, ScanCommand, DeleteCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";

export const config = { runtime: "nodejs20.x" };
const app = express();
app.use(cors({
  origin: [
    'http://localhost:5173',
    'https://hectoragomez.com',
  ],
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
  maxAge: 86400,
}));
app.use(express.json());


const requireJWT = jwtCheck({
  audience: process.env.AUTH0_AUDIENCE,
  issuerBaseURL: process.env.AUTH0_ISSUER_BASE_URL,
  tokenSigningAlg: 'RS256',
  jwksUri: `${process.env.AUTH0_ISSUER_BASE_URL}/.well-known/jwks.json`
});

// Disable caching for all routes in development
if (process.env.NODE_ENV === 'development') {
  app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    next();
  });
}

app.get("/health", (_req, res) => res.json({ ok: true }));

// GET /prompts - List available system prompts
app.get("/prompts", async (_req, res) => {
  try {
    const prompts = await listPrompts();
    res.json(prompts);
  } catch (e: any) {
    res.status(500).json({ error: e?.message || "internal_error" });
  }
});


// GET /isTokenValid?token=TOKEN&email=EMAIL
app.get("/isTokenValid", async (req: Request, res: Response) => {
  try {
    const tokenStr = String(req.query.token || "").trim();
    if (!tokenStr) return res.status(400).json({ error: "token is required" });

    // Get token details
    const tokenDoc = await loadActiveToken(tokenStr);
    const remaining = (tokenDoc.limit ?? 0) - (tokenDoc.used ?? 0);
    const provider = tokenDoc.provider;
    const email = tokenDoc.user_id;

    // Get user details
    const userResponse = await ddb().send(new ScanCommand({ 
      TableName: TABLES.Users,
      FilterExpression: "user_id = :uid",
      ExpressionAttributeValues: {
        ":uid": email
      }
    }));

    const user = userResponse.Items?.[0];
    const name = user?.name || email;

    res.json({ 
      valid: true, 
      remaining, 
      provider: provider.toUpperCase(),
      name,
      company: user?.company,
      email: user?.email || email
    });
  } catch (e: any) {
    const code = e?.message === "TOKEN_NOT_FOUND" ? 404 : (e?.message?.startsWith("TOKEN_") ? 403 : 500);
    res.status(code).json({ error: e?.message || "internal_error" });
  }
});

// GET /conversations?token=TOKEN[&conversation_id=ID][&user_id=UID][&all=true]
app.get("/conversations", async (req: Request, res: Response) => {
  try {
    const tokenStr = String(req.query.token || "").trim();
    if (!tokenStr) return res.status(400).json({ error: "token is required" });
    await loadActiveToken(tokenStr);
    const conversation_id = req.query.conversation_id ? String(req.query.conversation_id) : undefined;
    const user_id = req.query.email ? String(req.query.email) : undefined;
    const all = req.query.all === 'true';

    if (conversation_id) {
      const convo = await getConversation(conversation_id);
      if (!convo) return res.status(404).json({ error: "conversation not found" });
      return res.json({ valid: true, conversations: [convo] });
    }

    if (all) {
      const conversations = await getConversationsByTokenUser(tokenStr, user_id);
      return res.json({ valid: true, conversations });
    } else {
      const convo = await getLatestConversationByTokenUser(tokenStr, user_id);
      if (!convo) return res.status(404).json({ error: "conversation not found" });
      return res.json({ valid: true, conversations: [convo] });
    }
  } catch (e: any) {
    const code = e?.message === "TOKEN_NOT_FOUND" ? 404 : (e?.message?.startsWith("TOKEN_") ? 403 : 500);
    res.status(code).json({ error: e?.message || "internal_error" });
  }
});

// POST /completions { token, message, conversation_id?, user_id, promptId? }
app.post("/completions", async (req: Request, res: Response) => {
  try {
    const { token: tokenStr, message, conversationId, email, promptId, provider } = req.body || {};
    if (!tokenStr || !message || !email) return res.status(400).json({ error: "token, message, email are required" });

    const tokenDoc = await loadActiveToken(tokenStr);

    // ensure user (idempotent put)
    const nowIso = new Date().toISOString();
    await ddb().send(new PutCommand({
      TableName: TABLES.Users,
      Item: { email, createdAt: nowIso, updatedAt: nowIso },
      ConditionExpression: "attribute_not_exists(user_id)"
    })).catch(() => undefined);

    let convo = await ensureConversation(conversationId, tokenStr, email, provider);

    const remaining = (tokenDoc.limit ?? 0) - (tokenDoc.used ?? 0);
    if (remaining <= 0) return res.status(402).json({ error: "token_limit_exceeded", remaining: 0 });

    const userMsg: Message = { role: "user", content: String(message), createdAt: nowIso };
    const history: Message[] = [...(convo.messages || []), userMsg];

    const result = await runCompletion(provider, tokenDoc.model, history, promptId);
    const cost = result.estimatedTokens;
    if (cost > remaining) return res.status(402).json({ error: "token_limit_exceeded", remaining });

    const assistantMsg: Message = { role: "assistant", content: result.content, createdAt: new Date().toISOString() };

    if (conversationId !== convo.conversation_id) {
        const aiSummaryName = await runSmallModelForSummary(userMsg.content, assistantMsg.content);
        await renameConversation(convo.conversation_id, aiSummaryName);
        convo = await getConversation(convo.conversation_id) as typeof convo; // refresh with new name
    }

    await appendMessages(convo.conversation_id, [userMsg, assistantMsg]);
    await incrementTokenUsed(tokenStr, cost);

    res.json({ valid: true, conversationId: convo.conversation_id, message: assistantMsg, remaining: remaining - cost, displayName: convo.displayName });
  } catch (e: any) {
    const code = e?.message === "TOKEN_NOT_FOUND" ? 404 : (e?.message?.startsWith("TOKEN_") ? 403 : 500);
    res.status(code).json({ error: e?.message || "internal_error" });
  }
});

// PUT /delete?token=TOKEN&conversationId=ID { email }
app.put("/delete", async (req: Request, res: Response) => {
  try {
    const tokenStr = String(req.query.token || "").trim();
    const conversationId = String(req.query.conversationId || "").trim();
    const { email } = req.body || {};
    
    if (!tokenStr || !email) {
      return res.status(400).json({ error: "token and email required" });
    }

    // Verify token is valid
    await loadActiveToken(tokenStr);

    if (conversationId) {
      // Delete specific conversation
      const conversation = await getConversation(conversationId);
      if (!conversation) {
        return res.status(404).json({ error: "conversation not found" });
      }
      
      // Verify the conversation belongs to this user and token
      if (conversation.token !== tokenStr || conversation.user_id !== email) {
        return res.status(403).json({ error: "unauthorized to delete this conversation" });
      }

      await ddb().send(new DeleteCommand({ 
        TableName: TABLES.Conversations, 
        Key: { conversation_id: conversationId } 
      }));
      
      return res.json({ valid: true, conversationId });
    } else {
      // Delete all conversations for this token and user
      await deleteByTokenAndUser(tokenStr, email);
      return res.json({ deleted: true, all: true });
    }
  } catch (e: any) {
    const code = e?.message === "TOKEN_NOT_FOUND" ? 404 : (e?.message?.startsWith("TOKEN_") ? 403 : 500);
    res.status(code).json({ error: e?.message || "internal_error" });
  }
});

// Simple in-memory cache for user info
const userInfoCache = new Map<string, { data: any, expires: number }>();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes in milliseconds

async function getUserInfo(token: string) {
  // Check cache first
  const cached = userInfoCache.get(token);
  if (cached && cached.expires > Date.now()) {
    return cached.data;
  }

  // If not in cache or expired, fetch from Auth0
  const response = await fetch(`${process.env.AUTH0_ISSUER_BASE_URL}/userinfo`, {
    headers: { Authorization: `Bearer ${token}` }
  });

  if (!response.ok) {
    const error = await response.text();
    console.error('Failed to fetch user info:', error);
    throw new Error('Could not verify admin status');
  }

  const userInfo = await response.json();
  
  // Cache the result
  userInfoCache.set(token, {
    data: userInfo,
    expires: Date.now() + CACHE_TTL
  });

  return userInfo;
}

app.use('/admin', requireJWT, async (req: Request, res: Response, next: NextFunction) => {
  const token = req.headers?.authorization?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ error: 'No authorization token' });
  }

  try {
    const userInfo = await getUserInfo(token);

    const adminEmail = process.env.ADMIN_EMAIL;
    if (!adminEmail) {
      return res.status(500).json({ error: "ADMIN_EMAIL not configured" });
    }

    if (!userInfo.email || userInfo.email !== adminEmail) {
      return res.status(401).json({ error: "admin access required" });
    }

    // Store user info in request for downstream use
    req.auth = { ...req.auth, userInfo };
    next();
  } catch (error) {
    console.error('Error in admin middleware:', error);
    return res.status(500).json({ error: 'Internal server error verifying admin status' });
  }
});

app.get('/admin/profile', async (req: Request, res: Response) => {
  // Use cached user info from the admin middleware
  if (req.auth?.userInfo) {
    return res.json({ profile: req.auth.userInfo });
  }
  return res.status(500).json({ error: 'User info not available' });
});


// Admin endpoints
app.get("/admin/tables", async (_req: Request, res: Response) => {
  const [tokens, users, conversations] = await Promise.all([
    ddb().send(new ScanCommand({ TableName: TABLES.Tokens, Limit: 100 })).then(r => r.Items || []),
    ddb().send(new ScanCommand({ TableName: TABLES.Users, Limit: 100 })).then(r => r.Items || []),
    ddb().send(new ScanCommand({ TableName: TABLES.Conversations, Limit: 100 })).then(r => r.Items || []),
  ]);
  res.json({ tokens, users, conversations });
});

app.post("/admin/users", async (req: Request, res: Response) => {
  const { email, name, company } = req.body || {};
  if (!email) return res.status(400).json({ error: "email required" });
  const now = new Date().toISOString();
  const doc = { user_id: email, email, name, company, createdAt: now, updatedAt: now };
  await ddb().send(new PutCommand({ 
    TableName: TABLES.Users, 
    Item: doc, 
    ConditionExpression: "attribute_not_exists(user_id)"
  }));
  res.status(201).json(doc);
});

app.put("/admin/users/:email", async (req: Request, res: Response) => {
  try {
    const email = req.params.email;
    const { name, company, email: emailBody } = req.body || {};
    if (!email) return res.status(400).json({ error: "email required" });
    
    // Build update expression and attribute values dynamically
    const updateParts = [];
    const expressionAttributeNames: Record<string, string> = {
      "#ua": "updatedAt"
    };
    const expressionAttributeValues: Record<string, any> = {
      ":now": new Date().toISOString()
    };

    if (typeof name === 'string') {
      updateParts.push("#n = :name");
      expressionAttributeNames["#n"] = "name";
      expressionAttributeValues[":name"] = name;
    }

    if (typeof company === 'string') {
      updateParts.push("#c = :company");
      expressionAttributeNames["#c"] = "company";
      expressionAttributeValues[":company"] = company;
    }
    if (typeof emailBody === 'string') {
      updateParts.push("#e = :email");
      expressionAttributeNames["#e"] = "email";
      expressionAttributeValues[":email"] = emailBody;
    }

    // Always update updatedAt
    updateParts.push("#ua = :now");

    if (updateParts.length === 1) {
      return res.status(400).json({ error: "At least one field to update is required" });
    }

    const updateExpression = `SET ${updateParts.join(", ")}`;

    const result = await ddb().send(new UpdateCommand({
      TableName: TABLES.Users,
      Key: { user_id: email },
      UpdateExpression: updateExpression,
      ExpressionAttributeNames: expressionAttributeNames,
      ExpressionAttributeValues: expressionAttributeValues,
      ReturnValues: "ALL_NEW"
    }));

    res.json(result.Attributes);
  } catch (e: any) {
    const code = e?.name === "ConditionalCheckFailedException" ? 404 : 500;
    res.status(code).json({ error: e?.message || "internal_error" });
  }
});

app.delete("/admin/users/:email", async (req: Request, res: Response) => {
  const email = req.params.email;
  await ddb().send(new DeleteCommand({ TableName: TABLES.Users, Key: { user_id: email } }));
  res.json({ deleted: 1 });
});

import crypto from 'crypto';

function generateToken(user_id: string): string {
  // Generate 16 random bytes
  const randomBytes = crypto.randomBytes(16);
  
  // Create a timestamp component
  const timestamp = Date.now().toString(36);
  
  // Create a hash of the user_id
  const hash = crypto.createHash('sha256')
    .update(user_id + timestamp + randomBytes.toString('hex'))
    .digest('base64')
    // Make it URL safe
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
  
  // Take first 32 characters to keep it reasonable length
  return hash.slice(0, 32);
}

app.post("/admin/tokens", async (req: Request, res: Response) => {
  const { user_id, provider, model, limit, isActive = true, expiresAt } = req.body || {};
  if (!user_id || !provider || isNaN(limit)) return res.status(400).json({ error: "user_id, provider, limit required" });
  const token = generateToken(user_id);
  const now = new Date().toISOString();
  const doc = { token, user_id, provider, model, limit, used: 0, isActive, expiresAt, createdAt: now, updatedAt: now };
  await ddb().send(new PutCommand({ 
    TableName: TABLES.Tokens, 
    Item: doc, 
    ConditionExpression: "attribute_not_exists(#tk)",
    ExpressionAttributeNames: {
      "#tk": "token"
    }
  }));
  res.status(201).json(doc);
});

app.put("/admin/tokens/:token", async (req: Request, res: Response) => {
  try {
    const tokenStr = req.params.token;
    const { limit, isActive, provider } = req.body || {};
    
    // Build update expression and attribute values dynamically
    const updateParts = [];
    const expressionAttributeNames: Record<string, string> = {
      "#ua": "updatedAt"
    };
    const expressionAttributeValues: Record<string, any> = {
      ":now": new Date().toISOString()
    };

    if (!isNaN(limit)) {
      updateParts.push("#l = :limit");
      expressionAttributeNames["#l"] = "limit";
      expressionAttributeValues[":limit"] = limit;
    }

    if (typeof isActive === 'boolean') {
      updateParts.push("#ia = :isActive");
      expressionAttributeNames["#ia"] = "isActive";
      expressionAttributeValues[":isActive"] = isActive;
    }

    if (typeof provider === 'string') {
      updateParts.push("#p = :provider");
      expressionAttributeNames["#p"] = "provider";
      expressionAttributeValues[":provider"] = provider;
    }

    // Always update updatedAt
    updateParts.push("#ua = :now");

    if (updateParts.length === 1) {
      return res.status(400).json({ error: "At least one field to update is required" });
    }

    const updateExpression = `SET ${updateParts.join(", ")}`;

    const result = await ddb().send(new UpdateCommand({
      TableName: TABLES.Tokens,
      Key: { token: tokenStr },
      UpdateExpression: updateExpression,
      ExpressionAttributeNames: expressionAttributeNames,
      ExpressionAttributeValues: expressionAttributeValues,
      ReturnValues: "ALL_NEW"
    }));

    res.json(result.Attributes);
  } catch (e: any) {
    const code = e?.name === "ConditionalCheckFailedException" ? 404 : 500;
    res.status(code).json({ error: e?.message || "internal_error" });
  }
});

app.delete("/admin/tokens/:token", async (req: Request, res: Response) => {
  const tokenStr = req.params.token;
  await ddb().send(new DeleteCommand({ TableName: TABLES.Tokens, Key: { token: tokenStr } }));
  res.json({ deleted: 1 });
});

// Start server in development mode
if (process.env.NODE_ENV === 'development') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
  });
}

// Export handler for Vercel
export default function handler(req: VercelRequest, res: VercelResponse) {
  return (app as any)(req, res);
}