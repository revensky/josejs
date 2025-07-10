import { Buffer } from 'buffer';

import { InvalidJsonWebKeyException } from '../../exceptions/invalid-jsonwebkey.exception';
import { JsonWebKey } from '../../jwk/jsonwebkey';
import { EcJwkParameters } from '../jwk/ec/ec-jwk.parameters';
import { OctJwkParameters } from '../jwk/oct/oct-jwk.parameters';
import { JwsBackend } from './jws.backend';

Reflect.set(JwsBackend.prototype, 'algorithm', 'HS256');
Reflect.set(JwsBackend.prototype, 'keyType', 'oct');

describe('JSON Web Signature Backend', () => {
  const backend: JwsBackend = Reflect.construct(JwsBackend, []);

  describe('validateJsonWebKey()', () => {
    it('should throw when the json web key key type does not match the supported key type.', () => {
      const jwk = new JsonWebKey<EcJwkParameters>({
        kty: 'EC',
        crv: 'P-256',
        x: '4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og',
        y: 'mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8',
      });

      expect(() => backend['validateJsonWebKey'](jwk, 'sign')).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'The json web signature algorithm "HS256" only accepts "oct" json web keys.',
      );
    });

    it('should throw when the jws algorithm of the json web key does not match the algorithm of the backend.', () => {
      const jwk = new JsonWebKey<OctJwkParameters>({
        kty: 'oct',
        k: Buffer.alloc(64).toString('base64url'),
        alg: 'HS512',
      });

      expect(() => backend['validateJsonWebKey'](jwk, 'sign')).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'This json web key is intended to be used by the json web signature algorithm "HS512".',
      );
    });

    it('should throw when the json web key parameter "use" is not "sig".', () => {
      const jwk = new JsonWebKey<OctJwkParameters>({
        kty: 'oct',
        k: Buffer.alloc(32).toString('base64url'),
        use: 'enc',
      });

      expect(() => backend['validateJsonWebKey'](jwk, 'verify')).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'The provided json web key cannot be used by json web signatures.',
      );
    });

    it('should throw when the json web key parameter "key_ops" does not match the keyOp argument.', () => {
      const jwk = new JsonWebKey<OctJwkParameters>({
        kty: 'oct',
        k: Buffer.alloc(32).toString('base64url'),
        key_ops: ['verify'],
      });

      expect(() => backend['validateJsonWebKey'](jwk, 'sign')).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'The provided json web key cannot be used by json web signatures.',
      );
    });

    it('should validate the provided json web key.', () => {
      const jwk = new JsonWebKey<OctJwkParameters>({
        kty: 'oct',
        k: Buffer.alloc(32).toString('base64url'),
        use: 'sig',
        key_ops: ['sign', 'verify'],
      });

      expect(() => backend['validateJsonWebKey'](jwk, 'sign')).not.toThrow();
      expect(() => backend['validateJsonWebKey'](jwk, 'verify')).not.toThrow();
    });
  });
});
