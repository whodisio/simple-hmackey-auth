import { SimpleHmacKeyAuthError } from './SimpleHmacKeyAuthError';

/**
 * thrown when an authable request signature is found to be unauthentic
 * - authable = we have all of the data needed to check for authenticity
 * - unauthentic = we know this request should not be trusted
 */
export class UnauthenticRequestSignatureError extends SimpleHmacKeyAuthError {
  constructor(reason: string) {
    const message = `
Unauthentic request signature detected! ${reason}
    `.trim();
    super(message);
  }
}
