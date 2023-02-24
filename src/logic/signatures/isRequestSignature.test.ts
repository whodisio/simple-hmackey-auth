import { uuid } from '../../deps';
import { SimpleSignatureMetadata } from '../../domain/SimpleSignatureMetadata';
import { toHashSha256 } from '../hash/toHashSha256';
import { encodeRequestSignatureMetadata } from './encodeRequestSignatureMetadata';
import { isRequestSignature } from './isRequestSignature';

describe('isRequestSignature', () => {
  it('should return false if there are not exactly two parts', () => {
    const decision = isRequestSignature('a.b.c');
    expect(decision).toEqual(false);
  });
  it('should return false if the digest is not 64 char long', () => {
    const decision = isRequestSignature('a.b');
    expect(decision).toEqual(false);
  });
  it('should return false if the metadata can not be decoded', async () => {
    const decision = isRequestSignature(
      ['a', await toHashSha256('b')].join('.'),
    );
    expect(decision).toEqual(false);
  });
  it('should return true for a real request signature', async () => {
    const decision = isRequestSignature(
      [
        encodeRequestSignatureMetadata(
          new SimpleSignatureMetadata({
            clientPublicKey: 'pub_test',
            millisSinceEpoch: 821,
            nonce: uuid(),
          }),
        ),
        await toHashSha256('b'),
      ].join('.'),
    );
    expect(decision).toEqual(true);
  });
});
