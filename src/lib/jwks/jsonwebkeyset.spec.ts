import { Object } from '@revensky/primitives';

import { InvalidJsonWebKeySetException } from '../exceptions/invalid-jsonwebkeyset.exception';
import { JsonWebKeyNotFoundException } from '../exceptions/jsonwebkey-not-found.exception';
import { ECJsonWebKey } from '../jwa/jwk/ec/ec.jsonwebkey';
import { ECJsonWebKeyParameters } from '../jwa/jwk/ec/ec.jsonwebkey.parameters';
import { OCTJsonWebKey } from '../jwa/jwk/oct/oct.jsonwebkey';
import { OCTJsonWebKeyParameters } from '../jwa/jwk/oct/oct.jsonwebkey.parameters';
import { OKPJsonWebKey } from '../jwa/jwk/okp/okp.jsonwebkey';
import { OKPJsonWebKeyParameters } from '../jwa/jwk/okp/okp.jsonwebkey.parameters';
import { JsonWebKey } from '../jwk/jsonwebkey';
import { JsonWebKeySet } from './jsonwebkeyset';
import { JsonWebKeySetParameters } from './jsonwebkeyset.parameters';

const invalidJwkSets: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  'a',
  Symbol('a'),
  Buffer,
  Buffer.alloc(0),
  () => 1,
  {},
  [],
  [undefined, null, true, 1, 1.2, 1n, 'a', Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []],
];

describe('JSON Web Key Set', () => {
  describe('constructor', () => {
    it.each(invalidJwkSets)('should reject an invalid set of json web keys.', (jwkSet) => {
      expect(() => new JsonWebKeySet(jwkSet)).toThrowWithMessage(
        InvalidJsonWebKeySetException,
        'Invalid parameter "jwks".',
      );
    });

    it('should ensure all json web keys have identifiers.', () => {
      let jwks!: JsonWebKeySet;

      expect(() => {
        return (jwks = new JsonWebKeySet([
          new OCTJsonWebKey({ kty: 'oct', k: 'secret_one' }),
          new OCTJsonWebKey({ kty: 'oct', k: 'secret_two' }),
        ]));
      }).not.toThrow();

      expect(jwks.jwks).toStrictEqual(
        expect.arrayOf(
          expect.objectContaining<OCTJsonWebKeyParameters>({
            kty: 'oct',
            k: expect.toBeString(),
            kid: expect.toBeString(),
          }),
        ),
      );
    });

    it('should reject a set containing json web keys with duplicate json web key identifiers.', () => {
      const jwkSetWithRepeatedKeyIdentifiers: JsonWebKey[] = [
        new OCTJsonWebKey({ kty: 'oct', k: 'secret_one', kid: 'oct-key-id' }),
        new OCTJsonWebKey({ kty: 'oct', k: 'secret_two', kid: 'oct-key-id' }),
      ];

      expect(() => new JsonWebKeySet(jwkSetWithRepeatedKeyIdentifiers)).toThrowWithMessage(
        InvalidJsonWebKeySetException,
        'The use of duplicate JSON Web Key Identifiers is forbidden.',
      );
    });
  });

  describe('find()', () => {
    const jwks = new JsonWebKeySet([
      new OCTJsonWebKey({ kty: 'oct', k: 'secret_one', kid: 'oct-key-one', use: 'enc' }),
      new OCTJsonWebKey({ kty: 'oct', k: 'secret_two', kid: 'oct-key-two', use: 'sig' }),
    ]);

    it('should return null when no json web key matches the provided predicate.', () => {
      expect(jwks.find((jwk) => jwk.kid === 'unknown')).toBeNull();
    });

    it('should return the json web key that matches the provided predicate.', () => {
      expect(jwks.find((jwk) => jwk.kid === 'oct-key-one')).toBe(jwks.jwks[0]);
      expect(jwks.find((jwk) => jwk.use === 'sig')).toBe(jwks.jwks[1]);
    });
  });

  describe('get()', () => {
    const jwks = new JsonWebKeySet([
      new OCTJsonWebKey({ kty: 'oct', k: 'secret_one', kid: 'oct-key-one', use: 'enc' }),
      new OCTJsonWebKey({ kty: 'oct', k: 'secret_two', kid: 'oct-key-two', use: 'sig' }),
    ]);

    it('should throw when no json web key matches the provided predicate.', () => {
      expect(() => jwks.get((jwk) => jwk.kid === 'unknown')).toThrow(JsonWebKeyNotFoundException);
    });

    it('should return the json web key that matches the provided predicate.', () => {
      expect(jwks.get((jwk) => jwk.kid === 'oct-key-one')).toBe(jwks.jwks[0]);
      expect(jwks.get((jwk) => jwk.use === 'sig')).toBe(jwks.jwks[1]);
    });
  });

  describe('toJSON()', () => {
    const ecJwkParameters: ECJsonWebKeyParameters = {
      kty: 'EC',
      crv: 'P-256',
      x: '4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og',
      y: 'mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8',
      d: 'bwVX6Vx-TOfGKYOPAcu2xhaj3JUzs-McsC-suaHnFBo',
      kid: 'ec-key',
      use: 'enc',
    };

    const okpJwkParameters: OKPJsonWebKeyParameters = {
      kty: 'OKP',
      crv: 'Ed25519',
      x: 'aNoALKSUE1UsotuZvHUj1HEGqhpzLtsSTLmkBITDMAk',
      d: 'tccuS3jrlRwPaNsn2YxpUuMCqvnlsIgy_T0S7qVmo-A',
      kid: 'okp-key',
      use: 'sig',
    };

    const jwks = new JsonWebKeySet([new ECJsonWebKey(ecJwkParameters), new OKPJsonWebKey(okpJwkParameters)]);

    it('should be a plain javascript object with only the public parameters of the json web keys when no options are provided.', () => {
      const exportedJwksParameters = jwks.toJSON();

      expect(Object.isPlain(exportedJwksParameters)).toBeTrue();

      expect(exportedJwksParameters).toStrictEqual(
        expect.objectContaining<JsonWebKeySetParameters>({
          keys: expect.arrayContaining([
            expect.objectContaining<ECJsonWebKeyParameters>({
              kty: ecJwkParameters.kty,
              crv: ecJwkParameters.crv,
              x: ecJwkParameters.x,
              y: ecJwkParameters.y,
              kid: ecJwkParameters.kid,
              use: ecJwkParameters.use,
            }),
            expect.objectContaining<OKPJsonWebKeyParameters>({
              kty: okpJwkParameters.kty,
              crv: okpJwkParameters.crv,
              x: okpJwkParameters.x,
              kid: okpJwkParameters.kid,
              use: okpJwkParameters.use,
            }),
          ]),
        }),
      );
    });

    it('should be a plain javascript object with only the public parameters of the json web keys when options are provided.', () => {
      const exportedJwksParameters = jwks.toJSON({ exportPublicKeyOnly: true });

      expect(Object.isPlain(exportedJwksParameters)).toBeTrue();

      expect(exportedJwksParameters).toStrictEqual(
        expect.objectContaining<JsonWebKeySetParameters>({
          keys: expect.arrayContaining([
            expect.objectContaining<ECJsonWebKeyParameters>({
              kty: ecJwkParameters.kty,
              crv: ecJwkParameters.crv,
              x: ecJwkParameters.x,
              y: ecJwkParameters.y,
              kid: ecJwkParameters.kid,
              use: ecJwkParameters.use,
            }),
            expect.objectContaining<OKPJsonWebKeyParameters>({
              kty: okpJwkParameters.kty,
              crv: okpJwkParameters.crv,
              x: okpJwkParameters.x,
              kid: okpJwkParameters.kid,
              use: okpJwkParameters.use,
            }),
          ]),
        }),
      );
    });

    it('should be a plain javascript object with all the parameters of the json web keys.', () => {
      const exportedJwksParameters = jwks.toJSON({ exportPublicKeyOnly: false });

      expect(Object.isPlain(exportedJwksParameters)).toBeTrue();

      expect(exportedJwksParameters).toStrictEqual(
        expect.objectContaining<JsonWebKeySetParameters>({
          keys: expect.arrayContaining([
            expect.objectContaining<ECJsonWebKeyParameters>({
              kty: ecJwkParameters.kty,
              crv: ecJwkParameters.crv,
              x: ecJwkParameters.x,
              y: ecJwkParameters.y,
              d: ecJwkParameters.d,
              kid: ecJwkParameters.kid,
              use: ecJwkParameters.use,
            }),
            expect.objectContaining<OKPJsonWebKeyParameters>({
              kty: okpJwkParameters.kty,
              crv: okpJwkParameters.crv,
              x: okpJwkParameters.x,
              d: okpJwkParameters.d,
              kid: okpJwkParameters.kid,
              use: okpJwkParameters.use,
            }),
          ]),
        }),
      );
    });
  });
});
