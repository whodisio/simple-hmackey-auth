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

Using HMAC to sign requests increases the security of api-key authentication by ensuring that the `client-private-key` is not exposed through usage and that requests can't be replayed
- only the owner of the `client-private-key` can make requests against the server (blocks replay attacks)
- the `client-private-key` can not be leaked through usage, since it is never sent on the requests

Well known examples of this pattern in production:
- [AWS](http://s3.amazonaws.com/doc/s3-developer-guide/RESTAuthentication.html)
- [Twilio](https://www.twilio.com/docs/usage/security#validating-requests)
- [Google](https://cloud.google.com/storage/docs/authentication/hmackeys)


References:
- [HMAC: Keyed-Hashing for Message Authentication](https://www.rfc-editor.org/rfc/rfc2104)
- [What is HMAC Authentication and why is it useful?](https://www.wolfe.id.au/2012/10/20/what-is-hmac-authentication-and-why-is-it-useful/)
- [API Security: HMAC+Key vs JWT](https://softwareengineering.stackexchange.com/questions/297417/rest-api-security-hmac-key-hashing-vs-jwt)
- [HMAC](https://en.wikipedia.org/wiki/HMAC)


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

### Create an auth request signature

Creates a request signature that can be securely authed by the issuer. Useful any time you need to make an authable request (e.g., client side)

```ts
import { createRequestSignature } from 'simple-hmackey-auth';

const signature = await createRequestSignature({
  clientPrivateKey,
  request: {
    host: 'https://your.domain.com',
    endpoint: '/your/endpoint/...',
    headers,
    body,
  },
});
```


### Create authorization header

Creates an [authorization header](https://tools.ietf.org/html/rfc6750) which encodes all the data required by the issuer to auth the request, which you can add to your requests.

```ts
import { createAuthableAuthorizationHeader } from 'simple-hmackey-auth';

const { authorization } = await createAuthorizationHeader({
  clientPublicKey,
  clientPrivateKey,
  request: {
    host: 'https://your.domain.com',
    endpoint: '/your/endpoint/...',
    headers,
    body,
  },
});
```

To send authenticated requests, simply add that header to your requests.


### Assert authentic request signature

Checks whether the signature was authentic, from this client and for this request. Useful any time you need to make sure the request was authentic (e.g., server side)

```ts
import { assertAuthenticRequestSignature } from 'simple-hmackey-auth';

await assertAuthenticRequestSignature({
  signature,
  getClientPrivateKeyHash: async ({ clientPublicKey }) => {/** a method you define to lookup the private key hash from your database using the public key */},
  request: {
    host: 'https://your.domain.com',
    endpoint: '/your/endpoint/...,
    headers,
    body,
  },
});
```

Note: throws an `UnauthenticRequestSignature` error if the request was not authentic and explains what was unauthentic about it in the error message.

### Get signature from headers

This grabs the signature from the standard [authorization header](https://tools.ietf.org/html/rfc6750) header for you. Useful whenever you need to grab a signature from an HTTP request.

```ts
import { getRequestSignatureFromHeaders } from 'simple-hmackey-auth';
const signature = getRequestSignatureFromHeaders({ headers });
```

Request signatures are typically passed to apis through the `Authorization` header, following the [OAuth 2.0 Authorization Standard](https://tools.ietf.org/html/rfc6750) pattern, so this exposes an easy way to grab the token from there.


# Docs

### `fn:assertAuthenticRequestSignature({ signature: string, clientPublicKey: string, clientPrivateKeyHash: string | null, request: SignableRequest })`

Use this function when you want to authenticate a request that was made to you.

We check the authenticity of the request in the following ways:

- the signature is valid
  - by verifying the signature
    - check that we can verify the signature comes from the identified client, with the public key
    - check that the request header and payload have not been tampered with, with the signature
    - check that the token uses an asymmetric signing key, for secure decentralized authentication
  - by verifying the timestamps
    - check that the request was not possibly a replay or delay attack, for secure authentication
  - by verifying the nonce
    - check that the request was not a replay attack, for secure authentication
- the signing key is valid
  - by getting a client-private-key-hash for the client-public-key
    - checks implicitly that you did issue this keypair, since it was in your database, ensuring only keys you issued can be used to sign requests
    - checks implicitly that the key is not expired, since it was not removed from the database ⚠️, ensuring only active keys can be used to sign requests

Example:

```ts
import { assertAuthenticRequestSignature } from 'simple-hmackey-auth';
const claims = assertAuthenticRequestSignature({
  /**
   * the request signature you're checking the request for authenticity against
   */
  signature,

  /**
   * a method you define which can lookup the client-private-key-hash using the client-public-key
   */
  getRequestSignatureFromHeaders,

  /**
   * the request we will be checking against the signature to check it was not tampered with
   */
  request,
});
```
