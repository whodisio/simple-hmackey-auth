import { SimpleSignableRequest } from '../../domain/SimpleSignableRequest';
import { toHashSha256 } from '../hash/toHashSha256';

/**
 * computes the hmac digest intended for use in a secure request's signature
 *
 * def
 * - > digest: The output of a hash function (e.g., hash(data) = digest). Also known as a message digest
 *   - https://csrc.nist.gov/glossary/term/hash_digest
 *
 * ref
 * - https://stackoverflow.com/questions/3696857/whats-the-difference-between-message-digest-message-authentication-code-and-h
 */
export const computeSecureRequestSignatureHmacDigest = async ({
  clientPublicKey,
  clientPrivateKeyHash,
  nonce,
  millisSinceEpoch,
  request,
}: {
  clientPublicKey: string;
  clientPrivateKeyHash: string;
  nonce: string;
  millisSinceEpoch: number;
  request: SimpleSignableRequest;
}) =>
  await toHashSha256(
    JSON.stringify({
      // include the public key for extra precaution. there's no security vulnerability this prevents, but there's no reason not to
      clientPublicKey,

      // include the private key, in order to make this an HMAC
      clientPrivateKeyHash,

      // include the nonce, to ensure the integrity of the readable nonce which is used to prevent replay attacks
      nonce,

      // include the milliseconds since epoch timestamp, to ensure the integrity of the readable milliseconds since epoch timestamp which is also used to prevent replay attacks
      millisSinceEpoch,

      // and of course, include the request that we're signing for the integrity of
      request,
    }),
  );
