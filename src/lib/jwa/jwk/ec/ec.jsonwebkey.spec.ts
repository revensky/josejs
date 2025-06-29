import { Object } from '@revensky/primitives';

import { InvalidJsonWebKeyException } from '../../../exceptions/invalid-jsonwebkey.exception';
import { ECJsonWebKey } from './ec.jsonwebkey';
import { ECJsonWebKeyParameters } from './ec.jsonwebkey.parameters';

const jwkParameters: ECJsonWebKeyParameters = {
  kty: 'EC',
  crv: 'P-256',
  x: '4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og',
  y: 'mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8',
  d: 'bwVX6Vx-TOfGKYOPAcu2xhaj3JUzs-McsC-suaHnFBo',
};

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
  'unknown',
];

const invalidXs: any[] = [
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

const invalidYs: any[] = [
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

const invalidDs: any[] = [null, true, 1, 1.2, 1n, Symbol('foo'), Buffer, Buffer.alloc(1), () => 1, {}, [], ''];

describe('Elliptic Curve JSON Web Key', () => {
  describe('constructor', () => {
    it.each(invalidKtys)('should throw when the provided "kty" is invalid.', (kty) => {
      expect(() => new ECJsonWebKey({ ...jwkParameters, kty })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "kty".',
      );
    });

    it.each(invalidCrvs)('should throw when the provided "crv" is invalid.', (crv) => {
      expect(() => new ECJsonWebKey({ ...jwkParameters, crv })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "crv".',
      );
    });

    it.each(invalidXs)('should throw when the provided "x" is invalid.', (x) => {
      expect(() => new ECJsonWebKey({ ...jwkParameters, x })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "x".',
      );
    });

    it.each(invalidYs)('should throw when the provided "y" is invalid.', (y) => {
      expect(() => new ECJsonWebKey({ ...jwkParameters, y })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "y".',
      );
    });

    it.each(invalidDs)('should throw when the provided "d" is invalid.', (d) => {
      expect(() => new ECJsonWebKey({ ...jwkParameters, d })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "d".',
      );
    });

    it('should return an instance of an elliptic curve json web key.', () => {
      let jwk: ECJsonWebKey = null!; // just to please the compiler

      expect(() => (jwk = new ECJsonWebKey(jwkParameters))).not.toThrow();
      expect(jwk).toBeInstanceOf(ECJsonWebKey);
      expect(jwk).toMatchObject(jwkParameters);
    });
  });

  describe('generate()', () => {
    it.each(invalidCrvs)('should throw when passing an unsupported elliptic curve.', async (curve) => {
      await expect(ECJsonWebKey.generate({ curve })).rejects.toThrowWithMessage(
        TypeError,
        `Unsupported Elliptic Curve "${String(curve)}".`,
      );
    });

    it('should generate a P-256 elliptic curve json web key.', async () => {
      let jwk!: ECJsonWebKey;

      expect((jwk = await ECJsonWebKey.generate({ curve: 'P-256' }))).toBeInstanceOf(ECJsonWebKey);

      expect(jwk).toMatchObject<ECJsonWebKeyParameters>({
        kty: 'EC',
        crv: 'P-256',
        x: expect.toBeString(),
        y: expect.toBeString(),
        d: expect.toBeString(),
      });
    });

    it('should generate a P-384 elliptic curve json web key.', async () => {
      let jwk!: ECJsonWebKey;

      expect((jwk = await ECJsonWebKey.generate({ curve: 'P-384' }))).toBeInstanceOf(ECJsonWebKey);

      expect(jwk).toMatchObject<ECJsonWebKeyParameters>({
        kty: 'EC',
        crv: 'P-384',
        x: expect.toBeString(),
        y: expect.toBeString(),
        d: expect.toBeString(),
      });
    });

    it('should generate a P-521 elliptic curve json web key.', async () => {
      let jwk!: ECJsonWebKey;

      expect((jwk = await ECJsonWebKey.generate({ curve: 'P-521' }))).toBeInstanceOf(ECJsonWebKey);

      expect(jwk).toMatchObject<ECJsonWebKeyParameters>({
        kty: 'EC',
        crv: 'P-521',
        x: expect.toBeString(),
        y: expect.toBeString(),
        d: expect.toBeString(),
      });
    });
  });

  describe('toJSON()', () => {
    const jwk = new ECJsonWebKey(jwkParameters);

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
    it('should return an object with the parameters ["crv", "kty", "x", "y"] in this exact order.', () => {
      const jwk = new ECJsonWebKey(jwkParameters);
      const thumbprintParameters = Object.entries(jwk['getThumbprintParameters']());

      expect(thumbprintParameters).toStrictEqual<string[][]>([
        ['crv', jwk.crv],
        ['kty', jwk.kty],
        ['x', jwk.x],
        ['y', jwk.y],
      ]);
    });
  });
});
