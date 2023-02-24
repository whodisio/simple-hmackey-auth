import { uuid } from '../../deps';
import { SimpleSignatureMetadata } from '../../domain/SimpleSignatureMetadata';
import { toHashSha256 } from '../hash/toHashSha256';
import { encodeRequestSignatureMetadata } from '../signatures/encodeRequestSignatureMetadata';
import { getRequestSignatureFromHeaders } from './getRequestSignatureFromHeaders';

const getExampleSignature = async () =>
  [
    encodeRequestSignatureMetadata(
      new SimpleSignatureMetadata({
        clientPublicKey: 'pub_test',
        millisSinceEpoch: 821,
        nonce: uuid(),
      }),
    ),
    await toHashSha256('b'),
  ].join('.');

describe('getRequestSignatureFromHeaders', () => {
  it('should return null if there is no authorization header', () => {
    const signature = getRequestSignatureFromHeaders({
      headers: {},
    });
    expect(signature).toEqual(null);
  });
  it('should return null the authorization header contains something that does not look like a request signature', () => {
    const signature = getRequestSignatureFromHeaders({
      headers: {
        authorization: 'not_a_signature',
      },
    });
    expect(signature).toEqual(null);
  });
  it('should return the signature if it looks like a signature', async () => {
    const exampleSignature = await getExampleSignature();
    const signature = getRequestSignatureFromHeaders({
      headers: {
        authorization: exampleSignature,
      },
    });
    expect(signature).toEqual(exampleSignature);
  });
  it('should return the signature if it looks like a signature, even if its prefixed by something else', async () => {
    const exampleSignature = await getExampleSignature();
    const signature = getRequestSignatureFromHeaders({
      headers: {
        authorization: ['Bearer', exampleSignature].join(' '),
      },
    });
    expect(signature).toEqual(exampleSignature);
  });
  it('should return the signature if it looks like a signature, even if its prefixed by something else', async () => {
    const exampleSignature = await getExampleSignature();
    const signature = getRequestSignatureFromHeaders({
      headers: {
        authorization: ['HMAC', exampleSignature].join(' '),
      },
    });
    expect(signature).toEqual(exampleSignature);
  });
});
