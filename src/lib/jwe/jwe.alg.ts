/**
 * Supported JSON Web Encryption Key Management Algorithms.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.1 | JWE "alg" Parameter}
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4 | JWE Key Management Algorithms}
 */
export type JweAlg =
  | 'A128GCMKW'
  | 'A128KW'
  | 'A192GCMKW'
  | 'A192KW'
  | 'A256GCMKW'
  | 'A256KW'
  | 'ECDH-ES'
  | 'ECDH-ES+A128KW'
  | 'ECDH-ES+A192KW'
  | 'ECDH-ES+A256KW'
  | 'PBES2-HS256+A128KW'
  | 'PBES2-HS384+A192KW'
  | 'PBES2-HS512+A256KW'
  | 'RSA-OAEP'
  | 'RSA-OAEP-256'
  | 'RSA-OAEP-384'
  | 'RSA-OAEP-512'
  | 'RSA1_5'
  | 'dir';
