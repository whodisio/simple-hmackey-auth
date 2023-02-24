import { toHashSha256 } from '../hash/toHashSha256';
import { issueClientKeyPair } from './issueClientKeyPair';

describe('issueClientKeyPair', () => {
  describe('client public key', () => {
    it('should generate a public key that is distinguishable as public', async () => {
      const { clientPublicKey } = await issueClientKeyPair();
      expect(clientPublicKey.startsWith('pub_')).toBe(true);
    });
    it('should be unique each time', async () => {
      const { clientPublicKey: clientPublicKeyA } = await issueClientKeyPair();
      const { clientPublicKey: clientPublicKeyB } = await issueClientKeyPair();
      const { clientPublicKey: clientPublicKeyC } = await issueClientKeyPair();
      expect(clientPublicKeyA).not.toEqual(clientPublicKeyB);
      expect(clientPublicKeyB).not.toEqual(clientPublicKeyC);
    });
  });
  describe('client private key', () => {
    it('should generate a private key that is distinguishable as public', async () => {
      const { clientPrivateKey } = await issueClientKeyPair();
      expect(clientPrivateKey.startsWith('pri_')).toBe(true);
    });
    it('should be unique each time', async () => {
      const { clientPrivateKey: clientPrivateKeyA } =
        await issueClientKeyPair();
      const { clientPrivateKey: clientPrivateKeyB } =
        await issueClientKeyPair();
      const { clientPrivateKey: clientPrivateKeyC } =
        await issueClientKeyPair();
      expect(clientPrivateKeyA).not.toEqual(clientPrivateKeyB);
      expect(clientPrivateKeyB).not.toEqual(clientPrivateKeyC);
    });
  });
  describe('client private key hash', () => {
    it('should generate a hash which does not expose the client private key', async () => {
      const { clientPrivateKey, clientPrivateKeyHash } =
        await issueClientKeyPair();
      expect(clientPrivateKeyHash).not.toEqual(clientPrivateKey);
    });
    it('should generate a hash which we can compare against the private key for equality', async () => {
      const { clientPrivateKey, clientPrivateKeyHash } =
        await issueClientKeyPair();
      expect(clientPrivateKeyHash).toEqual(
        await toHashSha256(clientPrivateKey),
      );
    });
  });
});
