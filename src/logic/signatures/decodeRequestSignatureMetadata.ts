import { SimpleSignatureMetadata } from '../../domain/SimpleSignatureMetadata';
import { UnauthableRequestSignatureError } from '../../utils/errors/UnauthableRequestSignatureError';

export const decodeRequestSignatureMetadata = (
  signature: string,
): SimpleSignatureMetadata => {
  try {
    return new SimpleSignatureMetadata(
      JSON.parse(
        Buffer.from(signature.split('.')[0]!, 'base64url').toString('ascii'),
      ),
    );
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    throw new UnauthableRequestSignatureError(
      `could not decode request signature metadata: ${error.message}`,
    );
  }
};
