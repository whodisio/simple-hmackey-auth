# simple-hmackey-auth

A simple, convenient, and safe interface for using the HMAC Key pattern of authentication and authorization

Simple:

- exposes simple, declarative functions for each supported use case
- throws self explanatory errors when something goes wrong
- leverages open source standards to securely simplify the auth process

Safe:

- enforces best practices of HMAC Key authentication
- eliminates accidentally using HMAC Keys unsafely, by constraining exposed methods to secure and declarative use cases

In otherwords, it's built to provide [a pit of success](https://blog.codinghorror.com/falling-into-the-pit-of-success/)

---

# Background

HMAC Key authentication is a great way to implement authentication and authorization for SDK applications

HMAC Key authentication provides us the following guarantees on authenticated requests
- request integrity: the data sent by the client to the server has not tampered with
- request origination: the request comes to the server from a trusted client
- request originality: the request was not captured by an intruder and being replayed

Well known examples of this pattern in production:
- [AWS](http://s3.amazonaws.com/doc/s3-developer-guide/RESTAuthentication.html)
- [Twilio](https://www.twilio.com/docs/usage/security#validating-requests)
- [Google](https://cloud.google.com/storage/docs/authentication/hmackeys)

References:
- [HMAC: Keyed-Hashing for Message Authentication](https://www.rfc-editor.org/rfc/rfc2104)
- [What is HMAC Authentication and why is it useful?](https://www.wolfe.id.au/2012/10/20/what-is-hmac-authentication-and-why-is-it-useful/)
- [API Security: HMAC+Key vs JWT](https://softwareengineering.stackexchange.com/questions/297417/rest-api-security-hmac-key-hashing-vs-jwt)
- [HMAC](https://en.wikipedia.org/wiki/HMAC)
- [How and when do I use HMAC?](https://security.stackexchange.com/questions/20129/how-and-when-do-i-use-hmac)


Note: if you're looking to implement authentication and authorization for user facing applications, [JSON Web Tokens (JWTs)](https://github.com/whodisio/simple-jwt-auth) may be a better fit due to their [stateless and decentralized](https://softwareengineering.stackexchange.com/a/444092/146747) nature

---

# Install

```sh
npm install --save simple-hmackey-auth
```

# Example

### Issue a client key pair

Creates a client key pair that can be used by the client to send authable requests to the issuer.

```ts
import { issueClientKeyPair } from 'simple-hmackey-auth';

const {
  /**
   * the client-public-key identifies the keypair
   * - should be sent to client
   * - should be saved by issuer
   */
  clientPublicKey,

  /**
   * the client-private-key is the secret used by the client to sign requests
   * - should be sent to client
   * - should be irrecoverably forgotten by issuer
   */
  clientPrivateKey,

  /**
   * the client-private-key hash is a hash of the private-key that the issuer will use to auth requests
   * - is not needed by the client
   * - should be saved by the issuer, indexed by the client-public-key
   */
  clientPrivateKeyHash
} = await issueClientKeyPair();
```

### Create a secure request signature

Creates a request signature that can be securely authed by the issuer. Useful any time you need to make an authable request (e.g., client side)

Make sure to include any data that affects the outcome of the request in the request input to this function. The signature only ensures the integrity of the request data you told it about.

```ts
import { createSecureRequestSignature } from 'simple-hmackey-auth';

const signature = await createSecureRequestSignature({
  clientPublicKey,
  clientPrivateKey,
  request: {
    host: 'https://your.domain.com',
    endpoint: '/your/endpoint/...',
    headers,
    payload,
  },
});
```

### Assert request signature is authentic

Checks whether the signature was authentic via request origination and request integrity. Useful any time you need to make sure the request was authentic (e.g., server side)

Make sure to include any data that affects the outcome of the request in the request input to this function. The signature only ensures the integrity of the request data you told it about.

```ts
import { assertRequestSignatureAuthenticity } from 'simple-hmackey-auth';

await assertRequestSignatureAuthenticity({
  signature,
  getClientPrivateKeyHash: async ({ clientPublicKey }) => {/** a method you define to lookup the private key hash from your database using the public key */},
  setOriginalUsageOfNonce: async ({ nonce }) => {/** a method you define to record the first usage of the nonce and throw an error if it has already been used to stop replay attacks */}
  millisUntilExpiration: 5 * 60 * 1000, // the number of milliseconds allowed to elapse from the time the request was sent before we reject it to stop replay attacks
  request: {
    host: 'https://your.domain.com',
    endpoint: '/your/endpoint/...,
    headers,
    body,
  },
});
```

### Get signature from headers

This grabs the signature from the standard [authorization header](https://tools.ietf.org/html/rfc6750) header for you. Useful whenever you need to grab a signature from an HTTP request.

```ts
import { getRequestSignatureFromHeaders } from 'simple-hmackey-auth';
const signature = getRequestSignatureFromHeaders({ headers });
```

Request signatures are typically passed to apis through the `Authorization` header, following the [OAuth 2.0 Authorization Standard](https://tools.ietf.org/html/rfc6750) pattern, so this exposes an easy way to grab the token from there.


# Docs

### `fn:assertRequestSignatureAuthenticity({ signature: string, getClientPrivateKeyHash: ({ clientPublicKey }) => Promise<string>, request: SignableRequest })`

Use this function when you want to authenticate a request that was made to you.

We check the authenticity of the request in the following ways:
- request integrity
  - by verifying the signature against the request data, we prove that the data was not tampered with
- request origination
  - by verifying the signature against the shared secret's hash, we prove that the owner of the client-private-key made the request
  - by verifying the client-public-key identifies a client-secret-key-hash in your database, we prove that you issued the key used to sign the request and that you were the intended audience for the request
- request originality
  - by verifying the nonce has not already been seen for a request, we prove that this is the original request and not a replay attack
  - by verifying the millis-since-epoch of the request is recent enough, we add another mechanism of preventing replay attacks

This method will throw errors in the following cases
- an `UnauthableRequestSignatureError` is thrown if the request signature does not have the data required to check for authenticity
- an `UnauthenticRequestSignatureError` is thrown if we have successfully checked the request signature and found that the request is unauthentic


Example:

```ts
import { assertRequestSignatureAuthenticity } from 'simple-hmackey-auth';a

const claims = assertRequestSignatureAuthenticity({
  /**
   * the request signature you're checking the request for authenticity against
   */
  signature: string;

  /**
   * a method you define which can lookup the client-private-key-hash using the client-public-key
   */
  getClientPrivateKeyHash: ({}: { clientPublicKey: string }) => Promise<string>;

  /**
   * a method you define which records that a nonce has been used and throws an error if this is not the first time
   *
   * note
   * - if you choose to not define this method, your api will be vulnerable to replay attacks up to the millisUntilExpiration duration
   * - if your function does not correctly assert that the nonce has not been used before, your api will be vulnerable to replay attacks up to the millisUntilExpiration duration
   */
  setOriginalUsageOfNonce: ({}: { nonce: string }) => Promise<void>;

  /**
   * the number of milliseconds that could have passed since the timestamp on the request until we decide the request is expired
   *
   * note
   * - the longer this duration is, the more opportunity an attacker has to replay a request
   * - the default duration is 5 minutes
   */
  millisUntilExpiration: number;

  /**
   * the request we will be checking against the signature to check it was not tampered with
   */
  request: SimpleSignableRequest;
});
```
