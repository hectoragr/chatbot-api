import type { VercelRequest, VercelResponse } from "@vercel/node";
import express, { Request as ExpressRequest, NextFunction, Response } from "express";
import { auth as jwtCheck } from 'express-oauth2-jwt-bearer';
import * as dotenv from 'dotenv';
import helmet from "helmet";
import { Message } from "../src/lib/ddb.js";
import { loadActiveToken, incrementTokenUsed, createTokenIfNotExists, TokenDocReq, listTokens, listUnprocessedTokensRequest, deleteToken, updateToken, createTokenRequest, createTokenRequestMaxThreeTokens, transformTokenRequestToToken } from "../src/lib/tokens.js";
import { listPrompts } from "../src/lib/prompts.js";
import { ensureConversation, getConversation, getLatestConversationByTokenUser, getConversationsByTokenUser, appendMessages, deleteByTokenAndUser, runSmallModelForSummary, renameConversation, listConversations, deleteConversation, getConversationsByUserAndToken } from "../src/lib/conversations.js";
import { runCompletion } from "../src/lib/providers.js";
import { rateLimit, generateCSRFToken, verifyCSRFToken, hmac , randNonce, safeCompare, CSRF_TTL_MS, generateToken} from "../src/utils/utils.js";
import { createUserIfNotExists, deleteUserById, getUserById, listUsers, updateUser } from "../src/lib/users.js";
import { transform } from "zod";

dotenv.config();
const app = express();
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
}))

export type Request = ExpressRequest & {
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

// Create handler for Vercel deployment
export const createHandler = () => {
  return async (req: VercelRequest, res: VercelResponse): Promise<void> => {
    return new Promise((resolve, reject) => {
      app(req as any, res as any, (err?: any) => {
        if (err) {
          return reject(err);
        }
        resolve(undefined);
      });
    });
  };
};
const ALLOWED_ORIGINS = new Set([
  'http://localhost:5173',
  'https://chat.hectoragomez.com',
]);
app.use((req, res, next) => {
  const origin = req.headers.origin as string | undefined;
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-CSRF-Token');
    res.setHeader('Access-Control-Max-Age', '86400'); // 24 hours
  }
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  next();
});
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

app.get("/csrf", rateLimit(60, 30), async (req: Request, res: Response) => {
  try {
    const origin = Array.isArray(req.headers.origin) ? req.headers.origin[0] : req.headers.origin;
    const resp = generateCSRFToken(origin || "");
    res.json(resp);
  } catch (e: any) {
    res.status(500).json({ error: e?.message || "internal_error" });
  }
});

// GET /prompts - List available system prompts
app.get("/prompts", async (_req, res) => {
  try {
    const prompts = await listPrompts();
    res.json(prompts);
  } catch (e: any) {
    res.status(500).json({ error: e?.message || "internal_error" });
  }
});

app.get('/generateCaptcha', rateLimit(60, 30), async (_req, res) => {
  try {
    const a = Math.floor(Math.random() * 5) + 2;
    const b = Math.floor(Math.random() * 5) + 3;
    const captcha = { question: `What is ${a} + ${b}?`, answer: (a + b).toString() };
    const ts = new Date().toISOString();
    const nonce = randNonce();

    const answerHash = hmac(captcha.answer + ts + nonce);
    const payload = { answerHash, ts, nonce };
    const sig = hmac(JSON.stringify(payload));
    const token = Buffer.from(JSON.stringify({ ...payload, sig })).toString('base64url');

    res.json({ question: captcha.question, token, expiresIn: 2 * 60 * 1000 }); // valid for 2 minutes
  } catch (e: any) {
    res.status(500).json({ error: e?.message || "internal_error" });
  }
});

app.post('/requestToken', rateLimit(60, 10), async (req, res) => {
  try {
    const { email, name, provider, tokenLimit, company, captchaAnswer, captchaToken } = req.body || {};
    if (!email || !name || !provider || !tokenLimit || !captchaAnswer || !captchaToken) {
      return res.status(400).json({ error: 'email, name, provider, tokenLimit, captchaAnswer, and captchaToken are required' });
    }

    // Validate captcha
    let decoded: { answerHash: string; ts: string; nonce: string; sig: string } ;
    try {
      const decodedStr = Buffer.from(captchaToken, 'base64url').toString('utf-8');
      decoded = JSON.parse(decodedStr);
    } catch (e){
      console.log(e);
      return res.status(400).json({ error: 'Invalid captcha token' });
    }

    const { answerHash, ts, nonce, sig } = decoded;
    if (!answerHash || !ts || !nonce || !sig) {
      return res.status(400).json({ error: 'Invalid captcha token structure' });
    }

    // Check signature
    const expectedSig = hmac(JSON.stringify({ answerHash, ts, nonce }));
    const expectedAnswerHash = hmac(captchaAnswer + ts + nonce);
    if (!safeCompare(expectedSig, sig) || !safeCompare(expectedAnswerHash, answerHash)) {
      return res.status(400).json({ error: 'Invalid captcha token signature' });
    }
    const tsDate = new Date(ts);
    if (isNaN(tsDate.getTime()) || (Date.now() - tsDate.getTime()) > CSRF_TTL_MS) {
      return res.status(400).json({ error: 'Captcha token has expired' });
    }
    const tokenRequest = await createTokenRequestMaxThreeTokens(email, name, provider, tokenLimit, company);
    return res.json({ token: tokenRequest.token, message: `Token generated for ${email}. Use this token to start chatting.` });
  } catch (e) {
    console.log(e);
    return res.status(400).json({ error: 'Invalid captcha token' });
  }
  return res.status(500).json({ error: "internal_error" });
}); 

// GET /isTokenValid?token=TOKEN&email=EMAIL
app.get("/isTokenValid", rateLimit(60, 30), async (req: Request, res: Response) => {
  try {
    const tokenStr = String(req.query.token || "").trim();
    if (!tokenStr) return res.status(400).json({ error: "token is required" });

    // Get token details
    const tokenDoc = await loadActiveToken(tokenStr);
    const remaining = (tokenDoc.limit ?? 0) - (tokenDoc.used ?? 0);
    const provider = tokenDoc.provider;
    const email = tokenDoc.user_id;

    // Get user details
    const user = await getUserById(email);
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
    console.log(e);
    const code = e?.message === "TOKEN_NOT_FOUND" ? 404 : (e?.message?.startsWith("TOKEN_") ? 403 : 500);
    if (e?.message === "TOKEN_INACTIVE") {
      return res.status(403).json({ error: e?.message || "internal_error" });
    }
    res.status(code).json({ error: e?.message || "internal_error" });
  }
});

// GET /conversations?token=TOKEN[&conversation_id=ID][&user_id=UID][&all=true]
app.get("/conversations", rateLimit(60, 30), async (req: Request, res: Response) => {
  try {
    const tokenStr = String(req.query.token || "").trim();
    if (!tokenStr) return res.status(400).json({ error: "token is required" });
    await loadActiveToken(tokenStr);
    const conversation_id = req.query.conversation_id ? String(req.query.conversation_id) : undefined;
    const user_id = req.query.email ? String(req.query.email) : undefined;
    if (!user_id) return res.status(400).json({ error: "email is required" });
    const all = req.query.all === 'true';

    if (conversation_id) {
      const convo = await getConversation(conversation_id);
      if (!convo) return res.status(404).json({ error: "conversation not found" });
      return res.json({ valid: true, conversations: [convo] });
    }

    if (all) {
      const conversations = await getConversationsByUserAndToken(user_id, tokenStr);
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
app.post("/completions", rateLimit(60, 30), verifyCSRFToken, async (req: Request, res: Response) => {
  try {
    const { token: tokenStr, message, conversationId, email, promptId, provider } = req.body || {};
    if (!tokenStr || !message || !email) return res.status(400).json({ error: "token, message, email are required" });

    const user = await getUserById(email);
    if (!user) {
      return res.status(404).json({ error: "user not found" });
    }
    const tokenDoc = await loadActiveToken(tokenStr);
    const nowIso = new Date().toISOString();
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
app.put("/delete", rateLimit(60, 30), verifyCSRFToken,async (req: Request, res: Response) => {
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

      await deleteConversation(conversationId);
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

app.use('/admin', requireJWT, rateLimit(60, 30), verifyCSRFToken, async (req: Request, res: Response, next: NextFunction) => {
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
  const [tokens, users, conversations, unprocessedTokens] = await Promise.all([
    listTokens(),
    listUsers(),
    listConversations(),
    listUnprocessedTokensRequest()
  ]);
  res.json({ tokens, users, conversations, unprocessedTokens });
});

app.post("/admin/users", async (req: Request, res: Response) => {
  const { email, name, company } = req.body || {};
  if (!email) return res.status(400).json({ error: "email required" });
  const now = new Date().toISOString();
  const created = await createUserIfNotExists(email, name, email, company);
  if (!created) {
    return res.status(409).json({ error: "User already exists" });
  }
  res.status(201).json({ user_id: email, email, name, company, createdAt: now, updatedAt: now });
});

app.put("/admin/users/:email", async (req: Request, res: Response) => {
  try {
    const email = req.params.email;
    const { name, company, email: emailBody } = req.body || {};
    if (!email) return res.status(400).json({ error: "email required" });

    const updated = await updateUser(email, name, emailBody, company);
    if (!updated) {
      return res.status(404).json({ error: "User not found" });
    }
    
    res.json(updated);
  } catch (e: any) {
    const code = e?.name === "ConditionalCheckFailedException" ? 404 : 500;
    res.status(code).json({ error: e?.message || "internal_error" });
  }
});

app.delete("/admin/users/:email", async (req: Request, res: Response) => {
  const email = req.params.email;
  const deleted = await deleteUserById(email);
  if (!deleted) {
    return res.status(404).json({ error: "User not found" });
  }
  res.json({ deleted: 1 });
});

app.post("/admin/tokens", async (req: Request, res: Response) => {
  const { user_id, provider, model, limit, isActive = true } = req.body || {};
  if (!user_id || !provider || isNaN(limit)) return res.status(400).json({ error: "user_id, provider, limit required" });
  const doc = await createTokenIfNotExists({ user_id, provider, model, limit, isActive, used: 0 } as TokenDocReq);
  console.log('Created token:', doc);
  if (!doc) return res.status(409).json({ error: "Token already exists" });
  res.status(201).json(doc);
});

app.put("/admin/tokens/:token", async (req: Request, res: Response) => {
  try {
    const tokenStr = req.params.token;
    const { limit, isActive, provider } = req.body || {};    
    await updateToken(tokenStr, { limit, isActive, provider } as Partial<TokenDocReq>);
    const updated = await loadActiveToken(tokenStr);
    res.json(updated);
  } catch (e: any) {
    const code = e?.name === "ConditionalCheckFailedException" ? 404 : 500;
    res.status(code).json({ error: e?.message || "internal_error" });
  }
});

app.delete("/admin/tokens/:token", async (req: Request, res: Response) => {
  const tokenStr = req.params.token;
  await deleteToken(tokenStr);
  res.json({ deleted: 1 });
});

app.put("/admin/approveToken/:tokenRequestId", async (req: Request, res: Response) => {
  try {
    const tokenRequestId = req.params.tokenRequestId;
    if (!tokenRequestId) return res.status(400).json({ error: "tokenRequestId required" });
    const transform = await transformTokenRequestToToken(tokenRequestId);
    if (!transform) return res.status(404).json({ error: "token request not found" });
    res.json(transform);
  } catch (e: any) {
    console.log(e);
    const code = e?.name === "ConditionalCheckFailedException" ? 404 : 500;
    res.status(code).json({ error: e?.message || "internal_error" });
  }
});

// Start server in development mode
if (process.env.NODE_ENV === 'development') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
  });
}

// Create a handler function that works with both Express and Vercel
const handler = async (req: VercelRequest, res: VercelResponse) => {
  return new Promise((resolve, reject) => {
    app(req as any, res as any, (err?: any) => {
      if (err) {
        return reject(err);
      }
      resolve(undefined);
    });
  });
};

// Export the handler for Vercel
export default handler;