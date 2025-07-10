import { Buffer } from 'buffer';
import { randomBytes, randomInt } from 'crypto';

import { InvalidJsonWebKeyException } from '../../../exceptions/invalid-jsonwebkey.exception';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { JwkKty } from '../../../jwk/jwk.kty';
import { OctJwkParameters } from '../../jwk/oct/oct-jwk.parameters';
import { HMACJwsBackend } from './hmac-jws.backend';

Reflect.set(HMACJwsBackend.prototype, 'algorithm', 'HS256');
Reflect.set(HMACJwsBackend.prototype, 'hash', 'sha256');
Reflect.set(HMACJwsBackend.prototype, 'keySize', 32);

const secretParameters: OctJwkParameters = {
  kty: 'oct',
  k: 'qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ',
};

describe('HMAC JSON Web Signature Backend', () => {
  const backend: HMACJwsBackend = Reflect.construct(HMACJwsBackend, []);
  const message = Buffer.from('Super secret message.');

  describe('keyType', () => {
    it('should have "oct" as its value.', () => {
      expect(backend['keyType']).toEqual<JwkKty>('oct');
    });
  });

  describe('verify()', () => {
    it('should return false when the length of the signature does not match the json web key secret size.', async () => {
      const jwk = new JsonWebKey<OctJwkParameters>(secretParameters);
      const signature: string = 'babecafe';

      await expect(backend.verify(Buffer.from(signature, 'base64url'), message, jwk)).resolves.toBeFalse();
    });

    it('should return false when the signature does not match the message.', async () => {
      const jwk = new JsonWebKey<OctJwkParameters>(secretParameters);
      const signature: string = 'oAyBwCxDDEWFoGLHWIxJzKSLXM2NHOlPXQHRpSiTpUk';

      await expect(backend.verify(Buffer.from(signature, 'base64url'), message, jwk)).resolves.toBeFalse();
    });
  });

  describe('sign() and verify()', () => {
    it('should return true when the signature matches the message.', async () => {
      const jwk = new JsonWebKey<OctJwkParameters>(secretParameters);
      const signature = await backend.sign(message, jwk);

      await expect(backend.verify(signature, message, jwk)).resolves.toBeTrue();
    });
  });

  describe('validateJsonWebKey()', () => {
    it('should throw when the json web key uses a small secret.', () => {
      const jwk = new JsonWebKey<OctJwkParameters>({
        kty: 'oct',
        k: randomBytes(randomInt(1, 32)).toString('base64url'),
      });

      expect(() => backend['validateJsonWebKey'](jwk, 'verify')).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'The json web key parameter "k" must have at least 32 bytes.',
      );
    });
  });
});
