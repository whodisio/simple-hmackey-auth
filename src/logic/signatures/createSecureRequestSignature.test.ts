import { uuid } from '../../deps';
import { SimpleSignatureMetadata } from '../../domain/SimpleSignatureMetadata';
import { createSecureRequestSignature } from './createSecureRequestSignature';
import { decodeRequestSignatureMetadata } from './decodeRequestSignatureMetadata';

describe('createRequestSignature', () => {
  it('should be able to create a request signature', async () => {
    const signature = await createSecureRequestSignature({
      clientPublicKey: ['pub', uuid()].join('_'),
      clientPrivateKey: ['pri', uuid()].join('_'),
      request: {
        host: 'https://some.website.com',
        endpoint: '/invoice/send',
        headers: {},
        payload: {
          invoiceUuid: uuid(),
        },
      },
    });
    expect(signature.length).toBeGreaterThan(64);
  });
  it('should be possible to extract metadata from the signature', async () => {
    const signature = await createSecureRequestSignature({
      clientPublicKey: ['pub', uuid()].join('_'),
      clientPrivateKey: ['pri', uuid()].join('_'),
      request: {
        host: 'https://some.website.com',
        endpoint: '/invoice/send',
        headers: {},
        payload: {
          invoiceUuid: uuid(),
        },
      },
    });
    const metadata = decodeRequestSignatureMetadata(signature);
    expect(metadata).toHaveProperty('clientPublicKey');
    expect(metadata).toHaveProperty('millisSinceEpoch');
    expect(metadata).toHaveProperty('nonce');
    expect(metadata).toBeInstanceOf(SimpleSignatureMetadata);
  });
});
