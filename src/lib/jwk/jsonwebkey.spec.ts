import { Object } from '@revensky/primitives';

import { InvalidJsonWebKeyException } from '../exceptions/invalid-jsonwebkey.exception';
import { JsonWebKey } from './jsonwebkey';
import { JwkKeyOp } from './jwk-keyop.type';
import { JwkUse } from './jwk-use.type';

const invalidUses: any[] = [true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];

const invalidKeyOps: any[] = [
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
  [true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []],
  ['sign', 'verify', 'sign'],
];

const invalidUseKeyOps: [JwkUse, JwkKeyOp[]][] = [
  ['enc', ['sign']],
  ['enc', ['verify']],
  ['enc', ['decrypt', 'sign']],
  ['sig', ['decrypt']],
  ['sig', ['deriveBits']],
  ['sig', ['deriveKey']],
  ['sig', ['encrypt']],
  ['sig', ['unwrapKey']],
  ['sig', ['wrapKey']],
  ['sig', ['sign', 'decrypt']],
];

const invalidAlgs: any[] = [true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidKids: any[] = [true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidX5Us: any[] = [true, 1, 1.2, 1n, 'a', Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidX5Cs: any[] = [true, 1, 1.2, 1n, 'a', Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidX5Ts: any[] = [true, 1, 1.2, 1n, 'a', Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidX5TS256s: any[] = [true, 1, 1.2, 1n, 'a', Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidJsonWebKeys: any[] = [true, 1, 1.2, 1n, 'a', Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];

describe('JSON Web Key', () => {
  describe('constructor', () => {
    it("should return the provided value if it's already a json web key object.", () => {
      const jwk = Reflect.construct(JsonWebKey, [{ kty: 'oct' }]);
      expect(Reflect.construct(JsonWebKey, [jwk])).toBe(jwk);
    });

    it.each(invalidUses)('should throw when the provided "use" is invalid.', (use) => {
      expect(() => Reflect.construct(JsonWebKey, [{ kty: 'oct', use }])).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "use".',
      );
    });

    it.each(invalidKeyOps)('should throw when the provided "key_ops" is invalid.', (keyOps) => {
      expect(() => Reflect.construct(JsonWebKey, [{ kty: 'oct', key_ops: keyOps }])).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "key_ops".',
      );
    });

    it.each(invalidAlgs)('should throw when the provided "alg" is invalid.', (alg) => {
      expect(() => Reflect.construct(JsonWebKey, [{ kty: 'oct', alg }])).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "alg".',
      );
    });

    it.each(invalidKids)('should throw when the provided "kid" is invalid.', (kid) => {
      expect(() => Reflect.construct(JsonWebKey, [{ kty: 'oct', kid }])).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "kid".',
      );
    });

    it.each(invalidX5Us)('should throw when the provided "x5u" is invalid.', (x5u) => {
      expect(() => Reflect.construct(JsonWebKey, [{ kty: 'oct', x5u }])).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "x5u".',
      );
    });

    it.each(invalidX5Cs)('should throw when the provided "x5c" is invalid.', (x5c) => {
      expect(() => Reflect.construct(JsonWebKey, [{ kty: 'oct', x5c }])).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "x5c".',
      );
    });

    it.each(invalidX5Ts)('should throw when the provided "x5t" is invalid.', (x5t) => {
      expect(() => Reflect.construct(JsonWebKey, [{ kty: 'oct', x5t }])).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "x5t".',
      );
    });

    it.each(invalidX5TS256s)('should throw when the provided "x5t#S256" is invalid.', (x5tS256) => {
      expect(() => Reflect.construct(JsonWebKey, [{ kty: 'oct', 'x5t#S256': x5tS256 }])).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "x5t#S256".',
      );
    });

    it.each(invalidUseKeyOps)(
      'should throw when there\'s an invalid combination of "use" and "key_ops".',
      (use, keyOps) => {
        expect(() => Reflect.construct(JsonWebKey, [{ kty: 'oct', use, key_ops: keyOps }])).toThrowWithMessage(
          InvalidJsonWebKeyException,
          'Invalid combination of "use" and "key_ops".',
        );
      },
    );

    it('should throw when the provided "alg" is unsupported.', () => {
      expect(() => Reflect.construct(JsonWebKey, [{ kty: 'oct', alg: 'unknown' }])).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Unsupported value for json web key parameter "alg".',
      );
    });
  });

  describe('isJsonWebKey()', () => {
    it('should return true if the provided value is a json web key object.', () => {
      const jwk = Reflect.construct(JsonWebKey, [{ kty: 'oct' }]);
      expect(JsonWebKey.isJsonWebKey(jwk)).toBeTrue();
    });

    it.each(invalidJsonWebKeys)(
      'should return false if the data is not a plain javascript object with a "kty" parameter.',
      (jwk) => expect(JsonWebKey.isJsonWebKey(jwk)).toBeFalse(),
    );

    it('should return true if the provided value is a plain javascript object with a "kty" parameter.', () => {
      expect(JsonWebKey.isJsonWebKey({ kty: 'oct' })).toBeTrue();
    });
  });

  describe('toJSON()', () => {
    const jwk = Reflect.construct(JsonWebKey, [{ kty: 'oct' }]) as JsonWebKey;

    it('should be a plain javascript object.', () => {
      expect(Object.isPlain(jwk.toJSON())).toBeTrue();
    });

    it('should not have any functions, symbols or undefineds.', () => {
      expect(
        Object.values(jwk.toJSON()).every((value) => !['function', 'symbol', 'undefined'].includes(typeof value)),
      ).toBeTrue();
    });
  });
});
