import { InvalidJsonWebKeyException } from '../../../exceptions/invalid-jsonwebkey.exception';
import { OkpJwkBackend } from './okp-jwk.backend';
import { OkpJwkParameters } from './okp-jwk.parameters';

const parameters: OkpJwkParameters = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: 'aNoALKSUE1UsotuZvHUj1HEGqhpzLtsSTLmkBITDMAk',
  d: 'tccuS3jrlRwPaNsn2YxpUuMCqvnlsIgy_T0S7qVmo-A',
};

const invalidKtys: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  Symbol('a'),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
  'unknown',
];

const invalidCrvs: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  Symbol('a'),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
  'unknown',
];

const invalidXs: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidDs: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];

describe('Octet Key Pair JSON Web Key Backend.', () => {
  const backend = new OkpJwkBackend();

  describe('supportedCurves', () => {
    it('should support the curves ["Ed25519", "Ed448", "X25519", "X448"].', () => {
      expect(backend['supportedCurves']).toStrictEqual(['Ed25519', 'Ed448', 'X25519', 'X448']);
    });
  });

  describe('validate()', () => {
    it.each(invalidKtys)('should throw when the provided "kty" is invalid.', (kty) => {
      expect(() => backend.validate({ ...parameters, kty })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "kty".',
      );
    });

    it.each(invalidCrvs)('should throw when the provided "crv" is invalid.', (crv) => {
      expect(() => backend.validate({ ...parameters, crv })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "crv".',
      );
    });

    it.each(invalidXs)('should throw when the provided "x" is invalid.', (x) => {
      expect(() => backend.validate({ ...parameters, x })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "x".',
      );
    });

    it.each(invalidDs)('should throw when the provided "d" is invalid.', (d) => {
      expect(() => backend.validate({ ...parameters, d })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "d".',
      );
    });

    it('should not throw when providing a valid json web key parameters object.', () => {
      expect(() => backend.validate(parameters)).not.toThrow();
    });
  });
});
