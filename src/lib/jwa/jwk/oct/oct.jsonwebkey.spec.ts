import { Object } from '@revensky/primitives';

import { InvalidJsonWebKeyException } from '../../../exceptions/invalid-jsonwebkey.exception';
import { OCTJsonWebKey } from './oct.jsonwebkey';
import { OCTJsonWebKeyParameters } from './oct.jsonwebkey.parameters';

const jwkParameters: OCTJsonWebKeyParameters = { kty: 'oct', k: 'qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ' };

const invalidKtys: any[] = [
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
  'unknown',
];

const invalidKs: any[] = [
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
  '',
];

const invalidLengths: any[] = [undefined, null, true, 1.2, 1n, Symbol('foo'), Buffer, Buffer.alloc(1), () => 1, {}, []];

describe('Octet Sequence JSON Web Key', () => {
  describe('constructor', () => {
    it.each(invalidKtys)('should throw when the provided "kty" is invalid.', (kty) => {
      expect(() => new OCTJsonWebKey({ ...jwkParameters, kty })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "kty".',
      );
    });

    it.each(invalidKs)('should throw when the provided "k" is invalid.', (k) => {
      expect(() => new OCTJsonWebKey({ ...jwkParameters, k })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "k".',
      );
    });

    it('should return an instance of an octet sequence json web key.', () => {
      let jwk: OCTJsonWebKey = null!; // just to please the compiler

      expect(() => (jwk = new OCTJsonWebKey(jwkParameters))).not.toThrow();
      expect(jwk).toBeInstanceOf(OCTJsonWebKey);
      expect(jwk).toMatchObject(jwkParameters);
    });
  });

  describe('generate()', () => {
    it.each(invalidLengths)('should throw when passing an invalid length.', async (length) => {
      await expect(OCTJsonWebKey.generate({ length })).rejects.toThrowWithMessage(
        TypeError,
        'The length must be an integer.',
      );
    });

    it('should throw when providing a length zero.', async () => {
      await expect(OCTJsonWebKey.generate({ length: 0 })).rejects.toThrowWithMessage(
        TypeError,
        'The length must be greater than zero.',
      );
    });

    it('should throw when providing a negative length.', async () => {
      await expect(OCTJsonWebKey.generate({ length: -1 })).rejects.toThrowWithMessage(
        TypeError,
        'The length must be greater than zero.',
      );
    });

    it('should generate an octet sequence json web key.', async () => {
      let jwk!: OCTJsonWebKey;

      expect((jwk = await OCTJsonWebKey.generate({ length: 32 }))).toBeInstanceOf(OCTJsonWebKey);

      expect(jwk).toMatchObject<OCTJsonWebKeyParameters>({ kty: 'oct', k: expect.toBeString() });
    });
  });

  describe('toJSON()', () => {
    const jwk = new OCTJsonWebKey(jwkParameters);

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

  describe('getThumbprintParameters()', () => {
    it('should return an object with the parameters ["k", "kty"] in this exact order.', () => {
      const jwk = new OCTJsonWebKey(jwkParameters);
      const thumbprintParameters = Object.entries(jwk['getThumbprintParameters']());

      expect(thumbprintParameters).toStrictEqual<string[][]>([
        ['k', jwk.k],
        ['kty', jwk.kty],
      ]);
    });
  });
});
