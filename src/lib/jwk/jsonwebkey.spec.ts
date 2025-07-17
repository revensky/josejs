import { Buffer } from 'buffer';

import { InvalidJsonWebKeyException } from '../exceptions/invalid-jsonwebkey.exception';
import { EcJwkBackend } from '../jwa/jwk/ec/ec-jwk.backend';
import { EcJwkParameters } from '../jwa/jwk/ec/ec-jwk.parameters';
import { JwkBackend } from '../jwa/jwk/jwk.backend';
import { OctJwkBackend } from '../jwa/jwk/oct/oct-jwk.backend';
import { OctJwkParameters } from '../jwa/jwk/oct/oct-jwk.parameters';
import { OkpJwkBackend } from '../jwa/jwk/okp/okp-jwk.backend';
import { RsaJwkBackend } from '../jwa/jwk/rsa/rsa-jwk.backend';
import { JsonWebKey } from './jsonwebkey';
import { JwkKeyOp } from './jwk.key-op';
import { JwkKty } from './jwk.kty';
import { JwkParameters } from './jwk.parameters';
import { JwkUse } from './jwk.use';

const parameters: JwkParameters = {
  kty: 'RSA',
  n:
    'x4XkZG29RQnO8USrLcCtCSBmimPLeyW0tm0Nm-mCCQ4Jx7iGB6gawlFe_aHpYpJK' +
    'JEZBb3L6WiopxRw0B1KVhCOkVBEWJkgoNzvFouNrjnFdgeWWm5lwpMHcWORHJedQ' +
    'WzPFJxnaABm3TZokZkpk43LPpYTMYOHxWOpQaYhFRYhlIxkUfutUeuy8-lOCiXiz' +
    'XAptO0MBWCgZqYtPIHcoEr0XVMOeSaKa3nY_lRrY1JAeIRU-BkF_4IbevUZas__v' +
    'LtHREJIblLrnK6mpZkhsuNx0cAXwyhcGHljOwjzHeXv3TvrdPLfD2481U07-YUAw' +
    'rBGCFdk-wBSPUnDcTJIe_w',
  e: 'AQAB',
};

const invalidJwkParameters: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  'a',
  Symbol('a'),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  [],
];

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

const invalidUses: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, [], 'unknown'];

const invalidKeyOps: any[] = [
  null,
  true,
  1,
  1.2,
  1n,
  'a',
  Symbol('a'),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
  [undefined],
  [null],
  [true],
  [1],
  [1.2],
  [1n],
  [Symbol('a')],
  [Buffer],
  [Buffer.alloc(1)],
  [() => 1],
  [{}],
  [[]],
  ['unknown'],
  ['sign', 'verify', 'sign'],
];

const invalidAlgs: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, [], 'unknown'];
const invalidKids: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidX5Us: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];

const invalidX5Cs: any[] = [
  null,
  true,
  1,
  1.2,
  1n,
  'a',
  Symbol('a'),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
  [undefined],
  [null],
  [true],
  [1],
  [1.2],
  [1n],
  [Symbol('a')],
  [Buffer],
  [Buffer.alloc(1)],
  [() => 1],
  [{}],
  [[]],
];

const invalidX5Ts: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidX5TS256s: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];

const invalidUseKeyOps: [JwkUse, JwkKeyOp[]][] = [
  ['enc', ['sign']],
  ['enc', ['verify']],
  ['enc', ['decrypt', 'sign']],
  ['sig', ['decrypt']],
  ['sig', ['encrypt']],
  ['sig', ['unwrapKey']],
  ['sig', ['wrapKey']],
  ['sig', ['sign', 'decrypt']],
];

describe('JSON Web Key', () => {
  describe('backends', () => {
    it('should have all supported json web key backends.', () => {
      expect(JsonWebKey['backends']).toStrictEqual<Record<JwkKty, JwkBackend>>({
        EC: expect.any(EcJwkBackend),
        OKP: expect.any(OkpJwkBackend),
        RSA: expect.any(RsaJwkBackend),
        oct: expect.any(OctJwkBackend),
      });
    });
  });

  describe('jwkUses', () => {
    it('should have all supported json web key public key uses.', () => {
      expect(JsonWebKey['jwkUses']).toStrictEqual<JwkUse[]>(['enc', 'sig']);
    });
  });

  describe('jwkKeyOps', () => {
    it('should have all supported json web key key operations.', () => {
      expect(JsonWebKey['jwkKeyOps']).toStrictEqual<JwkKeyOp[]>([
        'decrypt',
        'deriveBits',
        'deriveKey',
        'encrypt',
        'sign',
        'unwrapKey',
        'verify',
        'wrapKey',
      ]);
    });
  });

  describe('constructor', () => {
    it.each(invalidKtys)('should throw when the provided "kty" is invalid.', (kty) => {
      expect(() => new JsonWebKey({ ...parameters, kty })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "kty".',
      );
    });

    it.each(invalidUses)('should throw when the provided "use" is invalid.', (use) => {
      expect(() => new JsonWebKey({ ...parameters, use })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "use".',
      );
    });

    it.each(invalidKeyOps)('should throw when the provided "key_ops" is invalid.', (keyOps) => {
      expect(() => new JsonWebKey({ ...parameters, key_ops: keyOps })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "key_ops".',
      );
    });

    it.each(invalidAlgs)('should throw when the provided "alg" is invalid.', (alg) => {
      expect(() => new JsonWebKey({ ...parameters, alg })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "alg".',
      );
    });

    it.each(invalidKids)('should throw when the provided "kid" is invalid.', (kid) => {
      expect(() => new JsonWebKey({ ...parameters, kid })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "kid".',
      );
    });

    it.each(invalidX5Us)('should throw when the provided "x5u" is invalid.', (x5u) => {
      expect(() => new JsonWebKey({ ...parameters, x5u })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "x5u".',
      );
    });

    it.each(invalidX5Cs)('should throw when the provided "x5c" is invalid.', (x5c) => {
      expect(() => new JsonWebKey({ ...parameters, x5c })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "x5c".',
      );
    });

    it.each(invalidX5Ts)('should throw when the provided "x5t" is invalid.', (x5t) => {
      expect(() => new JsonWebKey({ ...parameters, x5t })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "x5t".',
      );
    });

    it.each(invalidX5TS256s)('should throw when the provided "x5t#S256" is invalid.', (x5tS256) => {
      expect(() => new JsonWebKey({ ...parameters, 'x5t#S256': x5tS256 })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "x5t#S256".',
      );
    });

    it.each(invalidUseKeyOps)(
      'should throw when providing an invalid combination of json web key parameters "use" and "key_ops".',
      (use, keyOps) => {
        expect(() => new JsonWebKey({ ...parameters, use, key_ops: keyOps })).toThrowWithMessage(
          InvalidJsonWebKeyException,
          'Invalid combination of json web key parameters "use" and "key_ops".',
        );
      },
    );

    it('should create an instance of a json web key.', () => {
      let jwk!: JsonWebKey;

      const jwkBackendValidate = jest.spyOn(RsaJwkBackend.prototype, 'validate');

      expect(() => (jwk = new JsonWebKey(parameters))).not.toThrow();

      expect(jwk).toBeInstanceOf(JsonWebKey);

      expect(jwk['backend']).toBeInstanceOf(RsaJwkBackend);
      expect(jwkBackendValidate).toHaveBeenCalledOnce();
      expect(jwkBackendValidate).toHaveBeenCalledWith(parameters);

      expect(jwk.parameters).toStrictEqual(parameters);
    });
  });

  describe('isJwk()', () => {
    it.each(invalidJwkParameters)('should return false when the provided data is not a plain object.', (data) => {
      expect(JsonWebKey.isJwk(data)).toBeFalse();
    });

    it('should return false when the provided data has no "kty" parameter.', () => {
      expect(JsonWebKey.isJwk({})).toBeFalse();
    });

    it.each(invalidKtys)('should return false when the provided data an invalid "kty" parameter.', (kty) => {
      expect(JsonWebKey.isJwk({ kty })).toBeFalse();
    });

    it('should return true when the provided data is a valid json web key parameters object.', () => {
      expect(JsonWebKey.isJwk({ kty: 'RSA' })).toBeTrue();
    });
  });

  describe('getThumbprint()', () => {
    it('should return the thumbprint of the json web key.', () => {
      expect(new JsonWebKey(parameters).getThumbprint('sha256').toString('base64url')).toEqual(
        '9xLGZzIbwEak5aeOAGPXdPLWR374N6ECJ91cNtw_qg8',
      );
    });
  });

  describe('toJSON()', () => {
    it('should return the parameters of a symmetric json web key.', () => {
      const jwkParameters: OctJwkParameters = {
        kty: 'oct',
        k: 'qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ',
      };

      const jwk = new JsonWebKey(jwkParameters);

      expect(jwk.toJSON()).toMatchObject(jwkParameters);
      expect(jwk.toJSON(true)).toMatchObject(jwkParameters);
    });

    it('should return the parameters of an asymmetric json web key.', () => {
      const publicJwkParameters: EcJwkParameters = {
        kty: 'EC',
        crv: 'P-256',
        x: '4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og',
        y: 'mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8',
      };

      const privateJwkParameters: EcJwkParameters = {
        ...publicJwkParameters,
        d: 'bwVX6Vx-TOfGKYOPAcu2xhaj3JUzs-McsC-suaHnFBo',
      };

      const publicJwk = new JsonWebKey(publicJwkParameters);
      const privateJwk = new JsonWebKey(privateJwkParameters);

      expect(publicJwk.toJSON()).toMatchObject(publicJwkParameters);
      expect(publicJwk.toJSON(true)).toMatchObject(publicJwkParameters);

      expect(privateJwk.toJSON()).toMatchObject(publicJwkParameters);
      expect(privateJwk.toJSON(true)).toMatchObject(privateJwkParameters);
    });
  });
});
