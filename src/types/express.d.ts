import { Request as ExpressRequest } from 'express';
import { RequestContext } from 'express-openid-connect';

declare global {
  namespace Express {
    interface Request extends ExpressRequest {
      oidc?: RequestContext;
    }
  }
}
