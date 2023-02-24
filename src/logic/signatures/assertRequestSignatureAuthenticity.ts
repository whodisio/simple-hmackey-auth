import { SimpleSignableRequest } from '../../domain/SimpleSignableRequest';
import { UnauthableRequestSignatureError } from '../../utils/errors/UnauthableRequestSignatureError';
import { UnauthenticRequestSignatureError } from '../../utils/errors/UnauthenticRequestSignatureError';
import { computeSecureRequestSignatureHmacDigest } from './computeSecureRequestSignatureHmacDigest';
import { decodeRequestSignatureMetadata } from './decodeRequestSignatureMetadata';
import { isRequestSignature } from './isRequestSignature';

export const assertRequestSignatureAuthenticity = async ({
  signature,
  getClientPrivateKeyHash,
  setOriginalUsageOfNonce,
  millisUntilExpiration = 5 * 60 * 1000,
  request,
}: {
  /**
   * the request signature you're checking the request for authenticity against
   */
  signature: string;

  /**
   * a method you define which can lookup the client-private-key-hash using the client-public-key
   */
  getClientPrivateKeyHash: ({}: { clientPublicKey: string }) => Promise<string>;

  /**
   * a method you define which records that a nonce has been used or throws an error if this is not the first time
   *
   * note
   * - if you choose to not define this method, your api will be vulnerable to replay attacks up to the millisUntilExpiration duration
   * - if your function does not correctly assert that the nonce has not been used before, your api will be vulnerable to replay attacks up to the millisUntilExpiration duration
   */
  setOriginalUsageOfNonce: ({}: { nonce: string }) => Promise<void>;

  /**
   * the number of milliseconds that could have passed since the timestamp on the request until we decide the request is expired
   *
   * note
   * - the longer this duration is, the more opportunity an attacker has to replay a request
   * - the default duration is 5 minutes
   */
  millisUntilExpiration?: number;

  /**
   * the request we will be checking against the signature to check it was not tampered with
   */
  request: SimpleSignableRequest;
}): Promise<void> => {
  // check that the signature looks like a request signature
  if (!isRequestSignature(signature))
    throw new UnauthableRequestSignatureError(
      'signature does not look like a request signature',
    );

  // grab the metadata from the signature
  const metadata = decodeRequestSignatureMetadata(signature);

  // check that the timestamp on the request is in the past. otherwise, the client sending these requests has an error and thinks it is in the future -> exposing a replay attack vulnerability
  if (metadata.millisSinceEpoch > new Date().getTime())
    throw new UnauthableRequestSignatureError(
      'the request claims to have been made in the future. likely, the clock on the requestor is running fast. this request is unauthable as otherwise it would open a replay attack vulnerability',
    );

  // check that the request is not expired
  const millisElapsedSinceOriginallyRequested =
    new Date().getTime() - metadata.millisSinceEpoch;
  if (millisElapsedSinceOriginallyRequested > millisUntilExpiration)
    throw new UnauthenticRequestSignatureError(
      'the time elapsed since this request was originally requested is greater than the expiration threshold',
    );

  // check that the nonce has not been used before
  if (setOriginalUsageOfNonce)
    await setOriginalUsageOfNonce({ nonce: metadata.nonce }).catch(() => {
      throw new UnauthenticRequestSignatureError(
        'could not guarantee this is the original usage of this nonce',
      );
    });

  // lookup the client private key hash from the client public key
  const clientPrivateKeyHash = await getClientPrivateKeyHash({
    clientPublicKey: metadata.clientPublicKey,
  }).catch(() => {
    throw new UnauthenticRequestSignatureError(
      'could not get client private key hash for this client public key',
    );
  });

  // compute the hmac digest for the claimed request data
  const digestExpected = await computeSecureRequestSignatureHmacDigest({
    clientPrivateKeyHash,
    clientPublicKey: metadata.clientPublicKey,
    millisSinceEpoch: metadata.millisSinceEpoch,
    nonce: metadata.nonce,
    request,
  });
  const digestReceived = signature.split('.')[1]!;
  if (digestExpected !== digestReceived)
    throw new UnauthenticRequestSignatureError(
      'the request signature digest received is different than expected. if you think this is a mistake, please check that the inputs you are asserting the authenticity of match what the client had signed. for example, a common source of error comes from the headers being modified by intermediate tools by the time it reaches the server.',
    );

  // if the all of the above pass, the signature is authentic 👍
};
