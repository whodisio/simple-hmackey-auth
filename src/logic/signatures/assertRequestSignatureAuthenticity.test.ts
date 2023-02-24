import { uuid } from '../../deps';
import { SimpleSignableRequest } from '../../domain/SimpleSignableRequest';
import { SimpleSignatureMetadata } from '../../domain/SimpleSignatureMetadata';
import { UnauthableRequestSignatureError } from '../../utils/errors/UnauthableRequestSignatureError';
import { UnauthenticRequestSignatureError } from '../../utils/errors/UnauthenticRequestSignatureError';
import { toHashSha256 } from '../hash/toHashSha256';
import { assertRequestSignatureAuthenticity } from './assertRequestSignatureAuthenticity';
import { computeSecureRequestSignatureHmacDigest } from './computeSecureRequestSignatureHmacDigest';
import { encodeRequestSignatureMetadata } from './encodeRequestSignatureMetadata';

const exampleRequest: SimpleSignableRequest = {
  host: 'https://some.website.com',
  endpoint: '/invoice/send',
  headers: {},
  payload: {
    invoiceUuid: uuid(),
  },
};

describe('assertRequestSignatureAuthenticity', () => {
  it('should throw an error if the signature does not have exactly two parts to it', async () => {
    try {
      await assertRequestSignatureAuthenticity({
        signature: 'a.b.c.',
        getClientPrivateKeyHash: async () => '__HASH__',
        setOriginalUsageOfNonce: async () => {},
        request: exampleRequest,
      });
      fail();
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      expect(error).toBeInstanceOf(UnauthableRequestSignatureError);
      expect(error.message).toContain(
        'signature does not look like a request signature',
      );
    }
  });
  it('should throw an error if the signature digest is not 64 char', async () => {
    try {
      await assertRequestSignatureAuthenticity({
        signature: 'a.b',
        getClientPrivateKeyHash: async () => '__HASH__',
        setOriginalUsageOfNonce: async () => {},
        request: exampleRequest,
      });
      fail();
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      expect(error).toBeInstanceOf(UnauthableRequestSignatureError);
      expect(error.message).toContain(
        'signature does not look like a request signature',
      );
    }
  });
  it('should throw an error if the metadata can not be decoded from the signature', async () => {
    try {
      await assertRequestSignatureAuthenticity({
        signature: ['a', await toHashSha256('b')].join('.'),
        getClientPrivateKeyHash: async () => '__HASH__',
        setOriginalUsageOfNonce: async () => {},
        request: exampleRequest,
      });
      fail();
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      expect(error).toBeInstanceOf(UnauthableRequestSignatureError);
      expect(error.message).toContain(
        'signature does not look like a request signature',
      );
    }
  });
  it('should throw an error if the millis since epoch on the request is in the future', async () => {
    try {
      await assertRequestSignatureAuthenticity({
        signature: [
          encodeRequestSignatureMetadata(
            new SimpleSignatureMetadata({
              clientPublicKey: 'pub_test',
              millisSinceEpoch: new Date().getTime() + 100,
              nonce: uuid(),
            }),
          ),
          await toHashSha256('b'),
        ].join('.'),
        getClientPrivateKeyHash: async () => '__HASH__',
        setOriginalUsageOfNonce: async () => {},
        request: exampleRequest,
      });
      fail();
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      expect(error).toBeInstanceOf(UnauthableRequestSignatureError);
      expect(error.message).toContain(
        'the request claims to have been made in the future',
      );
      expect(error.message).toContain(
        'this request is unauthable as otherwise it would open a replay attack vulnerability',
      );
    }
  });
  it('should throw an error if the elapsed duration since originally sent exceeds the threshold', async () => {
    try {
      await assertRequestSignatureAuthenticity({
        signature: [
          encodeRequestSignatureMetadata(
            new SimpleSignatureMetadata({
              clientPublicKey: 'pub_test',
              millisSinceEpoch: new Date().getTime() - 1000,
              nonce: uuid(),
            }),
          ),
          await toHashSha256('b'),
        ].join('.'),
        getClientPrivateKeyHash: async () => '__HASH__',
        setOriginalUsageOfNonce: async () => {},
        millisUntilExpiration: 900,
        request: exampleRequest,
      });
      fail();
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      expect(error).toBeInstanceOf(UnauthenticRequestSignatureError);
      expect(error.message).toContain(
        'the time elapsed since this request was originally requested is greater than the expiration threshold',
      );
    }
  });
  it('should throw an error if the nonce had been used before', async () => {
    try {
      await assertRequestSignatureAuthenticity({
        signature: [
          encodeRequestSignatureMetadata(
            new SimpleSignatureMetadata({
              clientPublicKey: 'pub_test',
              millisSinceEpoch: new Date().getTime() - 1000,
              nonce: uuid(),
            }),
          ),
          await toHashSha256('b'),
        ].join('.'),
        getClientPrivateKeyHash: async () => '__HASH__',
        setOriginalUsageOfNonce: async () => {
          throw new Error('nonce was used'); // any error from this function will trigger nonce usage failure
        },
        request: exampleRequest,
      });
      fail();
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      expect(error).toBeInstanceOf(UnauthenticRequestSignatureError);
      expect(error.message).toContain(
        'could not guarantee this is the original usage of this nonce',
      );
    }
  });
  it('should throw an error if the client private key hash could not be found', async () => {
    try {
      await assertRequestSignatureAuthenticity({
        signature: [
          encodeRequestSignatureMetadata(
            new SimpleSignatureMetadata({
              clientPublicKey: 'pub_test',
              millisSinceEpoch: new Date().getTime() - 1000,
              nonce: uuid(),
            }),
          ),
          await toHashSha256('b'),
        ].join('.'),
        getClientPrivateKeyHash: async () => {
          throw new Error('could not find it');
        },
        setOriginalUsageOfNonce: async () => {},
        request: exampleRequest,
      });
      fail();
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      expect(error).toBeInstanceOf(UnauthenticRequestSignatureError);
      expect(error.message).toContain(
        'could not get client private key hash for this client public key',
      );
    }
  });
  it('should throw an error if the request signature digest does not match what is expected for the request', async () => {
    try {
      await assertRequestSignatureAuthenticity({
        signature: [
          encodeRequestSignatureMetadata(
            new SimpleSignatureMetadata({
              clientPublicKey: 'pub_test',
              millisSinceEpoch: new Date().getTime() - 1000,
              nonce: uuid(),
            }),
          ),
          await toHashSha256('b'),
        ].join('.'),
        getClientPrivateKeyHash: async () => '__HASH__',
        setOriginalUsageOfNonce: async () => {},
        request: exampleRequest,
      });
      fail();
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      expect(error).toBeInstanceOf(UnauthenticRequestSignatureError);
      expect(error.message).toContain(
        'the request signature digest received is different than expected',
      );
    }
  });
  it('should not throw an error if the request signature is authentic for this request', async () => {
    const metadata = new SimpleSignatureMetadata({
      clientPublicKey: 'pub_test',
      millisSinceEpoch: new Date().getTime() - 1000,
      nonce: uuid(),
    });
    await assertRequestSignatureAuthenticity({
      signature: [
        encodeRequestSignatureMetadata(metadata),
        await computeSecureRequestSignatureHmacDigest({
          ...metadata,
          clientPrivateKeyHash: '__HASH__',
          request: exampleRequest,
        }),
      ].join('.'),
      getClientPrivateKeyHash: async () => '__HASH__',
      setOriginalUsageOfNonce: async () => {},
      request: exampleRequest,
    });
  });
});
