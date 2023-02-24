import { decodeRequestSignatureMetadata } from './decodeRequestSignatureMetadata';

export const isRequestSignature = (signature: string) => {
  // if it doesn't have two parts, its not a request signature
  if (signature.split('.').length !== 2) return false;

  // if the digest is not exactly 64 characters long, its not a request signature (sha256 is 64 char)
  if (signature.split('.')[1]?.length !== 64) return false;

  // if we could not decode request signature metadata, its not a request signature
  try {
    decodeRequestSignatureMetadata(signature);
  } catch {
    return false;
  }

  // if we can do all of the above, then its a request signature
  return true;
};
