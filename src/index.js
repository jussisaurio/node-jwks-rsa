import { JwksClient } from './JwksClient';

import * as errors from './errors/index';
import { hapiJwt2Key as h, hapiJwt2KeyAsync as h2 } from './integrations/hapi';
import { expressJwtSecret as e } from './integrations/express';
import { koaJwtSecret as k } from './integrations/koa';

export default (options) => {
  return new JwksClient(options);
};

export const ArgumentError = errors.ArgumentError;
export const JwksError = errors.JwksError;
export const JwksRateLimitError = errors.JwksRateLimitError;
export const SigningKeyNotFoundError = errors.SigningKeyNotFoundError;

export const expressJwtSecret = e;
export const hapiJwt2Key = h;
export const hapiJwt2KeyAsync = h2;
export const koaJwtSecret = k;
