import { Object } from '@revensky/primitives';

import { JsonWebKeyNotFoundException } from '../exceptions/jsonwebkey-not-found.exception';
import { JsonWebKey } from '../jwk/jsonwebkey';
import { JwksParameters } from './jwks.parameters';

/**
 * JSON Web Key Set Implementation.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html | JSON Web Key Set}
 */
export class JsonWebKeySet {
  /**
   * JSON Web Keys registered at the JSON Web Key Set.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-5.1 | JWKS "keys" Parameter}
   */
  public readonly keys: JsonWebKey[];

  /**
   * Instantiates a new JSON Web Key Set.
   */
  public constructor();

  /**
   * Instantiates a new JSON Web Key Set based on the provided parameters.
   *
   * @param parameters JSON Web Key Set Parameters.
   */
  public constructor(parameters: JwksParameters);

  /**
   * Instantiates a new JSON Web Key Set with the provided JSON Web Keys.
   *
   * @param keys JSON Web Keys.
   */
  public constructor(keys: JsonWebKey[]);

  /**
   * Instantiates a new JSON Web Key Set based on the provided data.
   *
   * @param parametersOrKeys JSON Web Key Set Parameters of JSON Web Keys.
   */
  public constructor(parametersOrKeys?: JwksParameters | JsonWebKey[]) {
    switch (true) {
      case typeof parametersOrKeys === 'undefined':
        this.keys = [];
        break;

      case Array.isArray(parametersOrKeys) && parametersOrKeys.every((key) => key instanceof JsonWebKey):
        this.keys = parametersOrKeys;
        break;

      case JsonWebKeySet.isJwks(parametersOrKeys):
        this.keys = parametersOrKeys.keys.map((jwkParameters) => new JsonWebKey(jwkParameters));
        break;

      default:
        throw new TypeError('Invalid argument "parametersOrKeys".');
    }
  }

  /**
   * Checks if the provided data is a valid JSON Web Key Set Parameters object.
   *
   * @param data Data to be checked.
   * @returns Whether or not the provided data is a valid JSON Web Key Set Parameters object.
   */
  public static isJwks(data: unknown): data is JwksParameters {
    return (
      Object.isPlain(data) &&
      Object.hasOwn(data, 'keys') &&
      Array.isArray(Reflect.get(data, 'keys')) &&
      (<unknown[]>Reflect.get(data, 'keys')).every((key) => JsonWebKey.isJwk(key))
    );
  }

  /**
   * Finds and returns a JSON Web Key that satisfies the provided predicate.
   *
   * @param predicate Predicate used to locate the requested JSON Web Key.
   * @returns JSON Web Key that satisfies the provided predicate.
   */
  public find<T extends JsonWebKey>(predicate: (key: JsonWebKey) => boolean): T | null {
    return <T>this.keys.find(predicate) ?? null;
  }

  /**
   * Finds and returns a JSON Web Key that satisfies the provided predicate or throws an exception if none is found.
   *
   * @param predicate Predicate used to locate the requested JSON Web Key.
   * @returns JSON Web Key that satisfies the provided predicate.
   */
  public get<T extends JsonWebKey>(predicate: (key: JsonWebKey) => boolean): T {
    const key = this.find<T>(predicate);

    if (key === null) {
      throw new JsonWebKeyNotFoundException();
    }

    return key;
  }

  /**
   * Returns the Parameters of the JSON Web Key Set.
   *
   * @param privateKey Exports the parameters of the Private Keys together with the Public Keys.
   * @returns JSON Web Key Set Parameters.
   */
  public toJSON(privateKey?: true): JwksParameters {
    return { keys: this.keys.map((key) => key.toJSON(privateKey)) };
  }
}
