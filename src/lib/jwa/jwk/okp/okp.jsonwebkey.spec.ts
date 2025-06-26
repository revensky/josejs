import { Object } from '@revensky/primitives';

import { InvalidJsonWebKeyException } from '../../../exceptions/invalid-jsonwebkey.exception';
import { OKPJsonWebKey } from './okp.jsonwebkey';
import { OKPJsonWebKeyParameters } from './okp.jsonwebkey.parameters';

const jwkParameters: OKPJsonWebKeyParameters = {
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
  'a',
  Symbol('foo'),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
];

const invalidCrvs: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  Symbol('foo'),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
  'any',
];

const invalidXs: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol('foo'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidDs: any[] = [null, true, 1, 1.2, 1n, Symbol('foo'), Buffer, Buffer.alloc(1), () => 1, {}, []];

describe('Octet Key Pair JSON Web Key', () => {
  describe('constructor', () => {
    it.each(invalidKtys)('should throw when the provided "kty" is invalid.', (kty) => {
      expect(() => new OKPJsonWebKey({ ...jwkParameters, kty })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "kty".',
      );
    });

    it.each(invalidCrvs)('should throw when the provided "crv" is invalid.', (crv) => {
      expect(() => new OKPJsonWebKey({ ...jwkParameters, crv })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "crv".',
      );
    });

    it.each(invalidXs)('should throw when the provided "x" is invalid.', (x) => {
      expect(() => new OKPJsonWebKey({ ...jwkParameters, x })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "x".',
      );
    });

    it.each(invalidDs)('should throw when the provided "d" is invalid.', (d) => {
      expect(() => new OKPJsonWebKey({ ...jwkParameters, d })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "d".',
      );
    });

    it('should return an instance of an octet key pair json web key.', () => {
      let jwk: OKPJsonWebKey = null!; // just to please the compiler

      expect(() => (jwk = new OKPJsonWebKey(jwkParameters))).not.toThrow();
      expect(jwk).toBeInstanceOf(OKPJsonWebKey);
      expect(jwk).toMatchObject(jwkParameters);
    });
  });

  describe('toJSON()', () => {
    const jwk = new OKPJsonWebKey(jwkParameters);

    it('should be a plain javascript object.', () => {
      expect(Object.isPlain(jwk.toJSON())).toBeTrue();
    });

    it('should not have any functions, symbols or undefineds.', () => {
      expect(
        Object.values(jwk.toJSON()).every((value) => !['function', 'symbol', 'undefined'].includes(typeof value)),
      ).toBeTrue();
    });

    it('should return exactly the same parameters as provided in the constructor.', () => {
      expect(jwk.toJSON()).toStrictEqual(jwkParameters);
    });
  });
});
