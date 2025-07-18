import { Buffer } from 'buffer';

import { InvalidJoseHeaderException } from '../exceptions/invalid-jose-header.exception';
import { JoseHeader } from './jose.header';

const invalidJkus: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];

const invalidJwks: any[] = [
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
  {},
  { kty: undefined },
  { kty: null },
  { kty: true },
  { kty: 1 },
  { kty: 1.2 },
  { kty: 1n },
  { kty: Symbol('a') },
  { kty: Buffer },
  { kty: Buffer.alloc(1) },
  { kty: () => 1 },
  { kty: {} },
  { kty: [] },
  { kty: 'unknown' },
];

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
const invalidTyps: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidCtys: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];

const invalidCrits: any[] = [
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
  ['alg'],
  ['enc'],
  ['zip'],
  ['jku'],
  ['jwk'],
  ['kid'],
  ['x5u'],
  ['x5c'],
  ['x5t'],
  ['x5t#S256'],
  ['typ'],
  ['cty'],
  ['crit'],
  ['epk'],
  ['apu'],
  ['apv'],
  ['iv'],
  ['tag'],
  ['p2s'],
  ['p2c'],
  ['b64', 'b64'],
];

const invalidUnprotectedCrits: any[] = [
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
  {},
  [],
];

describe('JOSE Header', () => {
  describe('validateProtectedJoseHeader()', () => {
    it.each(invalidJkus)('should throw when the provided "jku" is invalid.', (jku) => {
      expect(() => JoseHeader.validateProtectedJoseHeader({ jku })).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "jku".',
      );
    });

    it.each(invalidJwks)('should throw when the provided "jwk" is invalid.', (jwk) => {
      expect(() => JoseHeader.validateProtectedJoseHeader({ jwk })).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "jwk".',
      );
    });

    it.each(invalidKids)('should throw when the provided "kid" is invalid.', (kid) => {
      expect(() => JoseHeader.validateProtectedJoseHeader({ kid })).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "kid".',
      );
    });

    it.each(invalidX5Us)('should throw when the provided "x5u" is invalid.', (x5u) => {
      expect(() => JoseHeader.validateProtectedJoseHeader({ x5u })).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "x5u".',
      );
    });

    it.each(invalidX5Cs)('should throw when the provided "x5c" is invalid.', (x5c) => {
      expect(() => JoseHeader.validateProtectedJoseHeader({ x5c })).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "x5c".',
      );
    });

    it.each(invalidX5Ts)('should throw when the provided "x5t" is invalid.', (x5t) => {
      expect(() => JoseHeader.validateProtectedJoseHeader({ x5t })).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "x5t".',
      );
    });

    it.each(invalidX5TS256s)('should throw when the provided "x5t#S256" is invalid.', (x5tS256) => {
      expect(() => JoseHeader.validateProtectedJoseHeader({ 'x5t#S256': x5tS256 })).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "x5t#S256".',
      );
    });

    it.each(invalidTyps)('should throw when the provided "typ" is invalid.', (typ) => {
      expect(() => JoseHeader.validateProtectedJoseHeader({ typ })).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "typ".',
      );
    });

    it.each(invalidCtys)('should throw when the provided "cty" is invalid.', (cty) => {
      expect(() => JoseHeader.validateProtectedJoseHeader({ cty })).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "cty".',
      );
    });

    it.each(invalidCrits)('should throw when the provided "crit" is invalid.', (crit) => {
      expect(() => JoseHeader.validateProtectedJoseHeader({ crit })).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "crit".',
      );
    });

    it('should throw when a parameter in "crit" is not present in the header.', () => {
      expect(() => JoseHeader.validateProtectedJoseHeader({ crit: ['b64'] })).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Missing required jose header parameter "b64".',
      );
    });
  });

  describe('validateUnprotectedJoseHeader()', () => {
    it.each(invalidJkus)('should throw when the provided "jku" is invalid.', (jku) => {
      expect(() => JoseHeader.validateUnprotectedJoseHeader({ jku })).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "jku".',
      );
    });

    it.each(invalidJwks)('should throw when the provided "jwk" is invalid.', (jwk) => {
      expect(() => JoseHeader.validateUnprotectedJoseHeader({ jwk })).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "jwk".',
      );
    });

    it.each(invalidKids)('should throw when the provided "kid" is invalid.', (kid) => {
      expect(() => JoseHeader.validateUnprotectedJoseHeader({ kid })).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "kid".',
      );
    });

    it.each(invalidX5Us)('should throw when the provided "x5u" is invalid.', (x5u) => {
      expect(() => JoseHeader.validateUnprotectedJoseHeader({ x5u })).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "x5u".',
      );
    });

    it.each(invalidX5Cs)('should throw when the provided "x5c" is invalid.', (x5c) => {
      expect(() => JoseHeader.validateUnprotectedJoseHeader({ x5c })).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "x5c".',
      );
    });

    it.each(invalidX5Ts)('should throw when the provided "x5t" is invalid.', (x5t) => {
      expect(() => JoseHeader.validateUnprotectedJoseHeader({ x5t })).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "x5t".',
      );
    });

    it.each(invalidX5TS256s)('should throw when the provided "x5t#S256" is invalid.', (x5tS256) => {
      expect(() => JoseHeader.validateUnprotectedJoseHeader({ 'x5t#S256': x5tS256 })).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "x5t#S256".',
      );
    });

    it.each(invalidTyps)('should throw when the provided "typ" is invalid.', (typ) => {
      expect(() => JoseHeader.validateUnprotectedJoseHeader({ typ })).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "typ".',
      );
    });

    it.each(invalidCtys)('should throw when the provided "cty" is invalid.', (cty) => {
      expect(() => JoseHeader.validateUnprotectedJoseHeader({ cty })).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "cty".',
      );
    });

    it.each(invalidUnprotectedCrits)('should throw when the provided "crit" is invalid.', (crit) => {
      expect(() => JoseHeader.validateUnprotectedJoseHeader({ crit })).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "crit".',
      );
    });

    it('should throw when providing both the parameters "jku" and "jwk".', () => {
      expect(() =>
        JoseHeader.validateUnprotectedJoseHeader({ jku: 'http://localhost', jwk: { kty: 'oct', k: 'secret_key' } }),
      ).toThrowWithMessage(
        InvalidJoseHeaderException,
        'The jose header parameters "jku" and "jwk" cannot be used together.',
      );
    });
  });
});
