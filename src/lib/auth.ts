import { Request as ExpressRequest, Response, NextFunction } from "express";
import { auth, ConfigParams } from 'express-openid-connect';
import { expressjwt as jwt } from "express-jwt";
import jwks from 'jwks-rsa';
import * as dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Extend Express Request type
type Request = ExpressRequest & {
  oidc?: {
    isAuthenticated(): boolean;
    user?: any;
    login(options: any): void;
    logout(options: any): void;
  };
};

// Check if Auth0 is configured
function isAuth0Configured() {
  const required = ['AUTH0_SECRET', 'AUTH0_CLIENT_ID', 'AUTH0_ISSUER_BASE_URL'];
  const missing = required.filter(key => !process.env[key]);
  if (missing.length > 0) {
    console.warn('Missing Auth0 configuration:', missing);
    return false;
  }
  return true;
}

// Frontend URL configuration
const FRONTEND_URL = process.env.NODE_ENV === 'development' 
  ? 'http://localhost:5173'
  : process.env.FRONTEND_URL || 'http://localhost:5173';

// Auth0 configuration
const config: ConfigParams = {
  authRequired: false,
  auth0Logout: true,
  baseURL: process.env.AUTH0_BASE_URL || 'http://localhost:3000',
  clientID: process.env.AUTH0_CLIENT_ID,
  issuerBaseURL: process.env.AUTH0_ISSUER_BASE_URL,
  secret: process.env.AUTH0_SECRET,
  clientSecret: process.env.AUTH0_CLIENT_SECRET,
  routes: {
    callback: '/api/auth/callback',
    postLogoutRedirect: FRONTEND_URL,
    login: '/api/auth/login',
    logout: '/api/auth/logout'
  },
  authorizationParams: {
    response_type: 'code',
    scope: 'openid profile email',
    audience: 'https://api.hectoragomez.com'
  },
  session: {
    absoluteDuration: 24 * 60 * 60, // 24 hours
    rolling: true
  },
  afterCallback: (_req, _res, session) => {
    if (session.error) {
      console.error('Auth0 callback error:', session.error);
      return session;
    }
    
    
    // After successful authentication, redirect to frontend
    const redirectUrl = new URL('/auth/callback', FRONTEND_URL);
    if (session.access_token) redirectUrl.searchParams.set('access_token', session.access_token);
    if (session.id_token) redirectUrl.searchParams.set('id_token', session.id_token);
    session.returnTo = redirectUrl.toString();
    return session;
  }
};

// JWT validation middleware
export const validateJWT = jwt({
  secret: jwks.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `${process.env.AUTH0_ISSUER_BASE_URL}/.well-known/jwks.json`
  }),
  audience: process.env.AUTH0_AUDIENCE,
  issuer: process.env.AUTH0_ISSUER_BASE_URL,
  algorithms: ['RS256']
});

// Initialize auth router
export const authRouter = isAuth0Configured() 
  ? auth(config) 
  : ((_req: Request, _res: Response, next: NextFunction) => next());

// Middleware to require authentication
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (!isAuth0Configured()) {
    console.warn('Auth0 is not configured - authentication is disabled');
    return next();
  }

  if (!req.oidc?.isAuthenticated()) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
}

// Middleware to require admin privileges
export function requireAdmin(
  req: ExpressRequest & { auth?: { payload?: any } },
  res: Response, 
  next: NextFunction
) {
  // First check if we have a valid JWT token
  if (!req.auth?.payload) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const adminEmail = process.env.ADMIN_EMAIL;
  if (!adminEmail) {
    console.error('ADMIN_EMAIL environment variable not set');
    return res.status(500).json({ error: "ADMIN_EMAIL not configured" });
  }


  // Check the custom namespace claim for the admin email
  const emailClaim = process.env.ADMIN_EMAIL_CLAIM || 'https://hectoragomez.com/email';
  const userEmail = req.auth.payload[emailClaim] || req.auth.payload.email;
    
  if (!userEmail || userEmail !== adminEmail) {
    return res.status(401).json({ error: "admin access required" });
  }

  next();
}

// Get user profile from request
export function getUserProfile(req: Request) {
  if (!isAuth0Configured()) {
    return null;
  }
  return req.oidc?.user || null;
}