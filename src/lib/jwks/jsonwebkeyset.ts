import { Object } from '@revensky/primitives';

import { InvalidJsonWebKeySetException } from '../exceptions/invalid-jsonwebkeyset.exception';
import { JsonWebKeyNotFoundException } from '../exceptions/jsonwebkey-not-found.exception';
import { JsonWebKey } from '../jwk/jsonwebkey';
import { JsonWebKeyParameters } from '../jwk/jsonwebkey.parameters';
import { JsonWebKeySetParameters } from './jsonwebkeyset.parameters';

/**
 * JSON Web Key Set Implementation.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html | RFC 7517}
 */
export class JsonWebKeySet {
  /**
   * JSON Web Keys registered at the JSON Web Key Set.
   */
  public readonly jwks!: JsonWebKey[];

  /**
   * Instantiates a new JSON Web Key Set based on the provided JSON Web Keys.
   *
   * @param jwks JSON Web Keys to be registered at the JSON Web Key Set.
   */
  public constructor(jwks: JsonWebKey[]) {
    if (!Array.isArray(jwks) || jwks.length === 0 || jwks.some((jwk) => !(jwk instanceof JsonWebKey))) {
      throw new InvalidJsonWebKeySetException('Invalid parameter "jwks".');
    }

    jwks.forEach((jwk) => (jwk.kid ??= jwk.getThumbprint().toString('base64url')));

    const identifiers = jwks.map((jwk) => jwk.kid);

    if (new Set(identifiers).size !== identifiers.length) {
      throw new InvalidJsonWebKeySetException('The use of duplicate JSON Web Key Identifiers is forbidden.');
    }

    this.jwks = jwks;
  }

  /**
   * Finds and returns a JSON Web Key that satisfies the provided predicate.
   *
   * @param predicate Predicate used to locate the requested JSON Web Key.
   * @returns JSON Web Key that satisfies the provided predicate.
   */
  public find<T extends JsonWebKey>(predicate: (jwk: JsonWebKeyParameters) => boolean): T | null {
    return <T>this.jwks.find(predicate) ?? null;
  }

  /**
   * Finds and returns a JSON Web Key that satisfies the provided predicate or throws an exception if none is found.
   *
   * @param predicate Predicate used to locate the requested JSON Web Key.
   * @returns JSON Web Key that satisfies the provided predicate.
   */
  public get<T extends JsonWebKey>(predicate: (jwk: JsonWebKeyParameters) => boolean): T {
    const jwk = this.find<T>(predicate);

    if (jwk === null) {
      throw new JsonWebKeyNotFoundException();
    }

    return jwk;
  }

  /**
   * Returns the Parameters of the JSON Web Key Set.
   */
  public toJSON(): JsonWebKeySetParameters {
    return Object.removeNullishValues<JsonWebKeySetParameters>({ keys: this.jwks.map((jwk) => jwk.toJSON()) });
  }
}
