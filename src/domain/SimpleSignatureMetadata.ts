import { DomainObject } from 'domain-objects';
import Joi from 'joi';

const schema = Joi.object().keys({
  clientPublicKey: Joi.string().required(),
  millisSinceEpoch: Joi.number().required(),
  nonce: Joi.string().required(),
});

/**
 * the readable, public metadata included in the signature which is used to authenticate the signature digest
 */
export interface SimpleSignatureMetadata {
  /**
   * the client public key is used by the authorizer to lookup the clientPrivateKeyHash to authenticate the signature - and to identify the client after authentication
   */
  clientPublicKey: string;

  /**
   * the millisSinceEpoch is used by the authorizer to check that the request is not being replayed, another way of eliminating replay attack vulnerabilities
   */
  millisSinceEpoch: number;

  /**
   * the nonce is used by the authorizer to check that the request is not being replayed, eliminating replay attack vulnerabilities
   */
  nonce: string;
}

export class SimpleSignatureMetadata
  extends DomainObject<SimpleSignatureMetadata>
  implements SimpleSignatureMetadata
{
  public static schema = schema;
}
