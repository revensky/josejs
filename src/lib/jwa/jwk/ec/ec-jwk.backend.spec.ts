import { InvalidJsonWebKeyException } from '../../../exceptions/invalid-jsonwebkey.exception';
import { EcJwkBackend } from './ec-jwk.backend';
import { EcJwkParameters } from './ec-jwk.parameters';

const parameters: EcJwkParameters = {
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
const invalidYs: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidDs: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];

describe('Elliptic Curve JSON Web Key Backend.', () => {
  const backend = new EcJwkBackend();

  describe('supportedCurves', () => {
    it('should support the curves ["P-256", "P-384", "P-521"].', () => {
      expect(backend['supportedCurves']).toStrictEqual(['P-256', 'P-384', 'P-521']);
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

    it.each(invalidYs)('should throw when the provided "y" is invalid.', (y) => {
      expect(() => backend.validate({ ...parameters, y })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "y".',
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
