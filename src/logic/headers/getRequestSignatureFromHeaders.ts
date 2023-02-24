import { isRequestSignature } from '../signatures/isRequestSignature';

export const getRequestSignatureFromHeaders = ({
  headers,
}: {
  headers: Record<string, any>;
}): string | null => {
  // grab the authorization header field
  const authorization = headers.authorization ?? headers.Authorization ?? null; // headers are case-insensitive, by spec: https://stackoverflow.com/a/5259004/3068233
  if (!authorization) return null;
  const potentiallyARequestSignature = authorization.split(' ').slice(-1)[0]; // the last part of the header is probably the signature
  if (!isRequestSignature(potentiallyARequestSignature)) return null; // check that it looks like a signature, since other strings can be passed here
  return potentiallyARequestSignature;
};
