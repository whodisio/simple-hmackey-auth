import { SimpleSignatureMetadata } from '../../domain/SimpleSignatureMetadata';

export const encodeRequestSignatureMetadata = (
  metadata: SimpleSignatureMetadata,
) => Buffer.from(JSON.stringify(metadata)).toString('base64url');
