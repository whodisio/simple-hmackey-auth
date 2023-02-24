import crypto from 'crypto';

/**
 * a simple function which converts a string into an sha256 hash
 *
 * note
 * - this can only be run on node
 */
export const toHashSha256 = async (message: string) =>
  crypto.createHash('sha256').update(message).digest('hex');
