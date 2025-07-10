import { Buffer } from 'buffer';

import { InvalidJsonWebKeyException } from '../../../exceptions/invalid-jsonwebkey.exception';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { JwkKty } from '../../../jwk/jwk.kty';
import { JwsAlg } from '../../../jws/jws.alg';
import { JwkCrv } from '../../jwk/jwk.crv';
import { OkpJwkParameters } from '../../jwk/okp/okp-jwk.parameters';
import { EdDSAJwsBackend } from './eddsa-jws.backend';

const publicParameters: OkpJwkParameters = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: 'g5p3LK1Mpb1lFnBDRlwvZPZSOnbGFSKnyngC7AOAsgE',
};

const privateParameters: OkpJwkParameters = {
  ...publicParameters,
  d: 'S52ag71xVm7aw2EQA2TWAJGsLKAecKVz2oJJVyK9FPA',
};

describe('EdDSA JSON Web Signature Backend', () => {
  const backend = new EdDSAJwsBackend();
  const message = Buffer.from('Super secret message.');

  describe('algorithm', () => {
    it('should have "EdDSA" as its value.', () => {
      expect(backend['algorithm']).toEqual<JwsAlg>('EdDSA');
    });
  });

  describe('keyType', () => {
    it('should have "OKP" as its value.', () => {
      expect(backend['keyType']).toEqual<JwkKty>('OKP');
    });
  });

  describe('curves', () => {
    it('should have ["Ed25519", "Ed448"] as its value.', () => {
      expect(backend['curves']).toStrictEqual<JwkCrv[]>(['Ed25519', 'Ed448']);
    });
  });

  describe('sign()', () => {
    it('should throw when signing with a public json web key.', async () => {
      const jwk = new JsonWebKey<OkpJwkParameters>(publicParameters);

      await expect(backend.sign(message, jwk)).rejects.toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Cannot use a public json web key for signing a message.',
      );
    });
  });

  describe('verify()', () => {
    it('should return false when the signature does not match the message.', async () => {
      const jwk = new JsonWebKey<OkpJwkParameters>(privateParameters);
      const signature: string = 'babecafe';

      await expect(backend.verify(Buffer.from(signature, 'base64url'), message, jwk)).resolves.toBeFalse();
    });
  });

  describe('sign() and verify()', () => {
    it('should return true when the signature matches the message.', async () => {
      const jwk = new JsonWebKey<OkpJwkParameters>(privateParameters);
      const signature = await backend.sign(message, jwk);

      await expect(backend.verify(signature, message, jwk)).resolves.toBeTrue();
    });
  });

  describe('validateJsonWebKey()', () => {
    it('should throw when the json web key uses an unsupported elliptic curve.', () => {
      const jwk = new JsonWebKey<OkpJwkParameters>({
        kty: 'OKP',
        crv: 'X25519',
        x: '6X4NNONlxaoZbUUZNTpp6x2ZROVHYiTeoUgvgzvAF04',
        d: 'MJ-UGvAjq6Sz5I4TPZ9OEVHsC4mUXOv54VxJNasAY3c',
      });

      expect(() => backend['validateJsonWebKey'](jwk, 'verify')).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'The json web signature algorithm "EdDSA" only accepts the elliptic curves ["Ed25519", "Ed448"].',
      );
    });
  });
});
