import { InvalidJsonWebKeySetException } from '../exceptions/invalid-jsonwebkeyset.exception';
import { OCTJsonWebKey } from '../jwa/jwk/oct/oct.jsonwebkey';
import { OCTJsonWebKeyParameters } from '../jwa/jwk/oct/oct.jsonwebkey.parameters';
import { JsonWebKey } from '../jwk/jsonwebkey';
import { JsonWebKeySet } from './jsonwebkeyset';

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
});
