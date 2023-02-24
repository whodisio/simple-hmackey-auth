import { uuid } from '../../deps';
import { computeSecureRequestSignatureHmacDigest } from './computeSecureRequestSignatureHmacDigest';

describe('computeSecureRequestSignatureHmacDigest', () => {
  it('should be able to compute a digest', async () => {
    const digest = await computeSecureRequestSignatureHmacDigest({
      clientPrivateKeyHash: uuid(),
      clientPublicKey: uuid(),
      nonce: uuid(),
      millisSinceEpoch: new Date().getTime(),
      request: {
        host: 'https://some.website.com',
        endpoint: '/invoice/send',
        headers: {},
        payload: {
          invoiceUuid: uuid(),
        },
      },
    });
    expect(digest.length).toEqual(64);
  });
});
