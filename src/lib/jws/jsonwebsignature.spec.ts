import { InvalidJoseHeaderException } from '../exceptions/invalid-jose-header.exception';
import { ES256JwsBackend } from '../jwa/jws/ecdsa/es256-jws.backend';
import { ES384JwsBackend } from '../jwa/jws/ecdsa/es384-jws.backend';
import { ES512JwsBackend } from '../jwa/jws/ecdsa/es512-jws.backend';
import { EdDSAJwsBackend } from '../jwa/jws/eddsa/eddsa-jws.backend';
import { HS256JwsBackend } from '../jwa/jws/hmac/hs256-jws.backend';
import { HS384JwsBackend } from '../jwa/jws/hmac/hs384-jws.backend';
import { HS512JwsBackend } from '../jwa/jws/hmac/hs512-jws.backend';
import { JwsBackend } from '../jwa/jws/jws.backend';
import { NoneJwsBackend } from '../jwa/jws/none/none-jws.backend';
import { PS256JwsBackend } from '../jwa/jws/rsassa/ps256-jws.backend';
import { PS384JwsBackend } from '../jwa/jws/rsassa/ps384-jws.backend';
import { PS512JwsBackend } from '../jwa/jws/rsassa/ps512-jws.backend';
import { RS256JwsBackend } from '../jwa/jws/rsassa/rs256-jws.backend';
import { RS384JwsBackend } from '../jwa/jws/rsassa/rs384-jws.backend';
import { RS512JwsBackend } from '../jwa/jws/rsassa/rs512-jws.backend';
import { JsonWebSignature } from './jsonwebsignature';
import { JwsAlg } from './jws.alg';

const invalidAlgs: any[] = [
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

const invalidJwsHeaders: any[] = [
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
  {},
  { alg: undefined },
  { alg: null },
  { alg: true },
  { alg: 1 },
  { alg: 1.2 },
  { alg: 1n },
  { alg: Symbol('a') },
  { alg: Buffer },
  { alg: Buffer.alloc(1) },
  { alg: () => 1 },
  { alg: {} },
  { alg: [] },
  { alg: 'unknown' },
];

describe('JSON Web Signature', () => {
  describe('backends', () => {
    it('should have all supported json web signature backends.', () => {
      expect(JsonWebSignature['backends']).toStrictEqual<Record<JwsAlg, JwsBackend>>({
        ES256: expect.any(ES256JwsBackend),
        ES384: expect.any(ES384JwsBackend),
        ES512: expect.any(ES512JwsBackend),
        EdDSA: expect.any(EdDSAJwsBackend),
        HS256: expect.any(HS256JwsBackend),
        HS384: expect.any(HS384JwsBackend),
        HS512: expect.any(HS512JwsBackend),
        PS256: expect.any(PS256JwsBackend),
        PS384: expect.any(PS384JwsBackend),
        PS512: expect.any(PS512JwsBackend),
        RS256: expect.any(RS256JwsBackend),
        RS384: expect.any(RS384JwsBackend),
        RS512: expect.any(RS512JwsBackend),
        none: expect.any(NoneJwsBackend),
      });
    });
  });

  describe('constructor', () => {
    it.each(invalidAlgs)('should throw when the provided header parameter "alg" is invalid.', (alg) => {
      expect(() => new JsonWebSignature({ alg }, Buffer.alloc(0))).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "alg".',
      );
    });

    it.each(invalidAlgs)('should throw when the provided protected headers parameter "alg" is invalid.', (alg) => {
      expect(() => {
        return new JsonWebSignature(
          [{ protectedHeader: { alg }, unprotectedHeader: { alg: 'ES256' } }],
          Buffer.alloc(0),
        );
      }).toThrowWithMessage(InvalidJoseHeaderException, 'Invalid jose header parameter "alg".');
    });

    it.each(invalidAlgs)('should throw when provided unprotected headers parameter "alg" is invalid.', (alg) => {
      expect(() => {
        return new JsonWebSignature(
          [{ protectedHeader: { alg: 'ES256' }, unprotectedHeader: { alg } }],
          Buffer.alloc(0),
        );
      }).toThrowWithMessage(InvalidJoseHeaderException, 'Invalid jose header parameter "alg".');
    });

    it('should throw when the protected and unprotected headers are not disjoint.', () => {
      expect(() => {
        return new JsonWebSignature(
          [{ protectedHeader: { alg: 'ES256' }, unprotectedHeader: { alg: 'ES256' } }],
          Buffer.alloc(0),
        );
      }).toThrowWithMessage(InvalidJoseHeaderException, 'The protected and unprotected jose headers must be disjoint.');
    });

    it.each(invalidAlgs)('should throw when the provided protected header parameter "alg" is invalid.', (alg) => {
      expect(() => new JsonWebSignature({ alg }, { alg: 'ES256' }, Buffer.alloc(0))).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "alg".',
      );
    });

    it.each(invalidAlgs)('should throw when the provided unprotected header parameter "alg" is invalid.', (alg) => {
      expect(() => new JsonWebSignature({ alg: 'ES256' }, { alg }, Buffer.alloc(0))).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "alg".',
      );
    });

    it('should throw when the protected header and the unprotected header are not disjoint.', () => {
      expect(() => new JsonWebSignature({ alg: 'ES256' }, { alg: 'ES256' }, Buffer.alloc(0))).toThrowWithMessage(
        InvalidJoseHeaderException,
        'The protected and unprotected jose headers must be disjoint.',
      );
    });
  });

  describe('isJwsHeader()', () => {
    it.each(invalidJwsHeaders)(
      'should return false when the provided data is an invalid json web signature jose header.',
      (header) => {
        expect(JsonWebSignature.isJwsHeader(header)).toBeFalse();
      },
    );

    it.each(Object.keys(JsonWebSignature['backends']))(
      'should return true when the provided data is a valid json web signature jose header.',
      (alg) => {
        expect(JsonWebSignature.isJwsHeader({ alg })).toBeTrue();
      },
    );
  });
});
