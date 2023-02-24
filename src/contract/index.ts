// methods
export { assertRequestSignatureAuthenticity } from '../logic/signatures/assertRequestSignatureAuthenticity';
export { createSecureRequestSignature } from '../logic/signatures/createSecureRequestSignature';
export { getRequestSignatureFromHeaders } from '../logic/headers/getRequestSignatureFromHeaders';
export { issueClientKeyPair } from '../logic/keys/issueClientKeyPair';

// utilities
export { decodeRequestSignatureMetadata } from '../logic/signatures/decodeRequestSignatureMetadata';
export { isRequestSignature } from '../logic/signatures/isRequestSignature';

// errors
export { UnauthenticRequestSignatureError } from '../utils/errors/UnauthenticRequestSignatureError';
export { UnauthableRequestSignatureError } from '../utils/errors/UnauthableRequestSignatureError';
export { SimpleHmacKeyAuthError } from '../utils/errors/SimpleHmacKeyAuthError';
