import { uuid } from '../../deps';
import { toHashSha256 } from '../hash/toHashSha256';

/**
 * creates a key-pair that can be given to the client to sign requests with
 */
export const issueClientKeyPair = async (): Promise<{
  /**
   * the client-public-key identifies the keypair
   * - should be sent to client
   * - should be saved by issuer
   */
  clientPublicKey: string;

  /**
   * the client-private-key is the secret used by the client to sign requests
   * - should be sent to client
   * - should be irrecoverably forgotten by issuer
   */
  clientPrivateKey: string;

  /**
   * the client-private-key hash is a hash of the private-key that the issuer will use to auth requests
   * - is not needed by the client
   * - should be saved by the issuer, indexed by the client-public-key
   */
  clientPrivateKeyHash: string;
}> => {
  // define the public key, based on a hashed uuid
  const clientPublicKey = ['pub', await toHashSha256(uuid())].join('_');

  // define the private key, also based on a hashed uuid
  const clientPrivateKey = ['pri', await toHashSha256(uuid())].join('_');

  // and hash the private key, so the issuer can save it in their database
  const clientPrivateKeyHash = await toHashSha256(clientPrivateKey);

  // and return the sets
  return {
    clientPublicKey,
    clientPrivateKey,
    clientPrivateKeyHash,
  };
};
