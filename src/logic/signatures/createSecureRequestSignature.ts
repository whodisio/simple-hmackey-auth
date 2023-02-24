import { SimpleHmacKeyAuthError } from '../../contract';
import { uuid } from '../../deps';
import { SimpleSignableRequest } from '../../domain/SimpleSignableRequest';
import { SimpleSignatureMetadata } from '../../domain/SimpleSignatureMetadata';
import { toHashSha256 } from '../hash/toHashSha256';
import { computeSecureRequestSignatureHmacDigest } from './computeSecureRequestSignatureHmacDigest';
import { encodeRequestSignatureMetadata } from './encodeRequestSignatureMetadata';

/**
 * creates a request signature that can be securely authenticated by the issuer
 */
export const createSecureRequestSignature = async ({
  clientPublicKey,
  clientPrivateKey,
  request,
}: {
  clientPublicKey: string;
  clientPrivateKey: string;
  request: SimpleSignableRequest;
}) => {
  // sanity check that the shape of the public key is correct
  if (!clientPublicKey.startsWith('pub_'))
    throw new SimpleHmacKeyAuthError('client public key must start with pub_');

  // sanity check that the shape of the private key is correct
  if (!clientPrivateKey.startsWith('pri_'))
    throw new SimpleHmacKeyAuthError('client private key must start with pri_');

  // define a timestamp for when this request was made, which can be used by server to prevent replay and delay attacks
  const millisSinceEpoch = new Date().getTime();

  // define a nonce for this request, which can be used by server to prevent replay attacks
  const nonce = uuid();

  // compute the hmac digest for this request's signature
  const digest = await computeSecureRequestSignatureHmacDigest({
    clientPrivateKeyHash: await toHashSha256(clientPrivateKey),
    clientPublicKey,
    millisSinceEpoch,
    nonce,
    request,
  });

  // define the readable metadata to be included in the signature
  const metadata = encodeRequestSignatureMetadata(
    new SimpleSignatureMetadata({
      clientPublicKey,
      millisSinceEpoch,
      nonce,
    }),
  );

  // create the signature from the digest and readable keys
  const signature = [metadata, digest].join('.');

  // return the signature
  return signature;
};
