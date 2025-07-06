/**
 * Supported JSON Web Encryption Content Encryption Algorithms.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.2 | JWE "enc" Parameter}
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-5 | JWE Content Encryption Algorithms}
 */
export type JweEnc = 'A128CBC-HS256' | 'A128GCM' | 'A192CBC-HS384' | 'A192GCM' | 'A256CBC-HS512' | 'A256GCM';
