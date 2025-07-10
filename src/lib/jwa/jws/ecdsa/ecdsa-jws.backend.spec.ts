import { Buffer } from 'buffer';

import { InvalidJsonWebKeyException } from '../../../exceptions/invalid-jsonwebkey.exception';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { JwkKty } from '../../../jwk/jwk.kty';
import { EcJwkParameters } from '../../jwk/ec/ec-jwk.parameters';
import { ECDSAJwsBackend } from './ecdsa-jws.backend';

Reflect.set(ECDSAJwsBackend.prototype, 'algorithm', 'ES256');
Reflect.set(ECDSAJwsBackend.prototype, 'hash', 'sha256');
Reflect.set(ECDSAJwsBackend.prototype, 'curve', 'P-256');

const publicParameters: EcJwkParameters = {
  kty: 'EC',
  crv: 'P-256',
  x: '4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og',
  y: 'mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8',
};

const privateParameters: EcJwkParameters = {
  ...publicParameters,
  d: 'bwVX6Vx-TOfGKYOPAcu2xhaj3JUzs-McsC-suaHnFBo',
};

describe('ECDSA JSON Web Signature Backend', () => {
  const backend: ECDSAJwsBackend = Reflect.construct(ECDSAJwsBackend, []);
  const message = Buffer.from('Super secret message.');

  describe('keyType', () => {
    it('should have "EC" as its value.', () => {
      expect(backend['keyType']).toEqual<JwkKty>('EC');
    });
  });

  describe('sign()', () => {
    it('should throw when signing with a public json web key.', async () => {
      const jwk = new JsonWebKey<EcJwkParameters>(publicParameters);

      await expect(backend.sign(message, jwk)).rejects.toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Cannot use a public json web key for signing a message.',
      );
    });
  });

  describe('verify()', () => {
    it('should return false when the signature does not match the message.', async () => {
      const jwk = new JsonWebKey<EcJwkParameters>(privateParameters);
      const signature: string = 'babecafe';

      await expect(backend.verify(Buffer.from(signature, 'base64url'), message, jwk)).resolves.toBeFalse();
    });
  });

  describe('sign() and verify()', () => {
    it('should return true when the signature matches the message.', async () => {
      const jwk = new JsonWebKey<EcJwkParameters>(privateParameters);
      const signature = await backend.sign(message, jwk);

      await expect(backend.verify(signature, message, jwk)).resolves.toBeTrue();
    });
  });

  describe('validateJsonWebKey()', () => {
    it('should throw when the json web key uses a different elliptic curve.', () => {
      const jwk = new JsonWebKey<EcJwkParameters>({
        kty: 'EC',
        crv: 'P-384',
        x: 'UaQhiO6Vy65pQ68T1rXkQp6lAj2kH-CW5SsmBffVQE6nv-EFvT01FrYcb2hqVqSO',
        y: 'j_QTT2TjtGpHO2BOm72_6JBWLXMKFNTBEAA_W8C459lMMSZMBnsfJPlEGE4MUJRJ',
        d: 'UIBXnR9aLPG05Cz1rCypivHEukUw2TsFyG34j2ZhQ7XLWaarmgNw-TIJjNZO6yh7',
      });

      expect(() => backend['validateJsonWebKey'](jwk, 'verify')).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'The json web signature algorithm "ES256" only accepts the elliptic curve "P-256".',
      );
    });
  });
});
