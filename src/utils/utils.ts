import crypto from "crypto";
import { z } from "zod";
import { loadRateLimit, updateRateLimit } from "../lib/rateLimits.js";
import type { NextFunction, Response } from "express";

// Use a more complete Request interface
interface CustomRequest {
    method: string;
    headers: {
        [key: string]: string | string[] | undefined;
        "x-csrf-token"?: string;
        "x-xsrf-token"?: string;
        "x-forwarded-for"?: string;
    };
    auth?: {
        userInfo?: { email?: string };
        payload?: { email?: string };
    };
}

const SEC = process.env.CSRF_SECRET || "change_this_secret";
export const CSRF_TTL_MS = 2 * 60 * 1000;  // 2 minutes

export function hmac(data: string) {
    return crypto.createHmac("sha256", SEC).update(data).digest("hex");
}

export function randNonce() {
    return crypto.randomBytes(16).toString("hex");
}

export function safeCompare(a: string, b: string) {
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

function clientId(req: CustomRequest) {
    const email = req.auth?.userInfo?.email || req.auth?.payload?.email;
    if (email) return `email:${email}`;
    const ip = req.headers?.["x-forwarded-for"] || "unknown";
    return `ip:${ip}`;
}

export function rateLimit(windowSec: number, maxRequests: number) {
    return async (req: CustomRequest, res: Response, next: NextFunction) => {
        if (process.env.NODE_ENV === "development") {
            return next();
        }

        const client = clientId(req);
        const key = `rate_limit:${client}:${Math.floor(Date.now() / 1000 / windowSec)}`;
        const rl = await loadRateLimit(key);

        if (rl.count >= maxRequests) {
            return res.status(429).json({ error: "Rate limit exceeded" });
        }

        const count = await updateRateLimit(key, 1, windowSec);
        if (count > maxRequests) {
            return res.status(429).json({ error: "Rate limit exceeded" });
        }
        res.setHeader("X-RateLimit-Limit", maxRequests.toString());
        res.setHeader("X-RateLimit-Remaining", Math.max(0, maxRequests - count).toString());
        return next();
    };
}

export function verifyCSRFToken(req: CustomRequest, res: Response, next: NextFunction) {
    if (process.env.NODE_ENV === "development") {
        return next();
    }
    
    const method = req.method.toUpperCase();
    if (method === "GET" || method === "HEAD" || method === "OPTIONS") {
        return next();
    }
    
    const token = req.headers["x-csrf-token"] || req.headers["x-xsrf-token"];
    if (!token || Array.isArray(token)) {
        return res.status(403).json({ error: "CSRF_TOKEN_MISSING" });
    }
    let decoded: string;
    try {
        decoded = Buffer.from(token, "base64url").toString("utf-8");
    } catch {
        return res.status(403).json({ error: "CSRF_TOKEN_INVALID" });
    }
    let parsed: { payload: string; sig: string };
    try {
        parsed = z.object({ payload: z.string(), sig: z.string() }).parse(JSON.parse(decoded));
    } catch {
        return res.status(403).json({ error: "CSRF_TOKEN_INVALID" });
    }
    const expectedSig = hmac(parsed.payload);   
    if (!safeCompare(expectedSig, parsed.sig)) {
        return res.status(403).json({ error: "CSRF_TOKEN_INVALID" });
    }
    next();
}

export function generateCSRFToken(origin: string) {
    const ts = Date.now().toString();
    const nonce = crypto.randomBytes(16).toString("hex");
    const payload = JSON.stringify({ origin, ts, nonce });
    const sig = hmac(payload);
    const token = Buffer.from(JSON.stringify({ payload, sig })).toString("base64url");
    return {token, expiresIn: CSRF_TTL_MS};
}

export function generateToken(user_id: string): string {
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