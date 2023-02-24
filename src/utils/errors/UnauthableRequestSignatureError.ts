import { SimpleHmacKeyAuthError } from './SimpleHmacKeyAuthError';

/**
 * thrown when we cant check the authenticity of a request signature
 * - unauthable = we don't have the data required to check for authenticity
 */
export class UnauthableRequestSignatureError extends SimpleHmacKeyAuthError {
  constructor(reason: string) {
    const message = `
Unauthable request signature detected! ${reason}
    `.trim();
    super(message);
  }
}
