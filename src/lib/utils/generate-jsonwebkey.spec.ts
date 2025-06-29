import { ECJsonWebKey } from '../jwa/jwk/ec/ec.jsonwebkey';
import { ECJsonWebKeyParameters } from '../jwa/jwk/ec/ec.jsonwebkey.parameters';
import { OCTJsonWebKey } from '../jwa/jwk/oct/oct.jsonwebkey';
import { OCTJsonWebKeyParameters } from '../jwa/jwk/oct/oct.jsonwebkey.parameters';
import { OKPJsonWebKey } from '../jwa/jwk/okp/okp.jsonwebkey';
import { OKPJsonWebKeyParameters } from '../jwa/jwk/okp/okp.jsonwebkey.parameters';
import { RSAJsonWebKey } from '../jwa/jwk/rsa/rsa.jsonwebkey';
import { RSAJsonWebKeyParameters } from '../jwa/jwk/rsa/rsa.jsonwebkey.parameters';
import { generateJsonWebKey } from './generate-jsonwebkey';

const invalidKtys: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  Symbol('foo'),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
  'unknown',
];

describe('generateJsonWebKey()', () => {
  it.each(invalidKtys)('should throw when the provided "kty" is invalid.', async (kty) => {
    await expect(generateJsonWebKey(kty, <any>{})).rejects.toThrowWithMessage(
      TypeError,
      `Unsupported JSON Web Key Type "${String(kty)}".`,
    );
  });

  it('should generate an elliptic curve json web key.', async () => {
    let jwk!: ECJsonWebKey;

    expect((jwk = await generateJsonWebKey('EC', { curve: 'P-256' }))).toBeInstanceOf(ECJsonWebKey);

    expect(jwk).toMatchObject<ECJsonWebKeyParameters>({
      kty: 'EC',
      crv: 'P-256',
      x: expect.toBeString(),
      y: expect.toBeString(),
      d: expect.toBeString(),
    });
  });

  it('should generate an octet key pair json web key.', async () => {
    let jwk!: OKPJsonWebKey;

    expect((jwk = await generateJsonWebKey('OKP', { curve: 'Ed25519' }))).toBeInstanceOf(OKPJsonWebKey);

    expect(jwk).toMatchObject<OKPJsonWebKeyParameters>({
      kty: 'OKP',
      crv: 'Ed25519',
      x: expect.toBeString(),
      d: expect.toBeString(),
    });
  });

  it('should generate an rsa json web key.', async () => {
    let jwk!: RSAJsonWebKey;

    expect((jwk = await generateJsonWebKey('RSA', { modulus: 2048 }))).toBeInstanceOf(RSAJsonWebKey);

    expect(jwk).toMatchObject<RSAJsonWebKeyParameters>({
      kty: 'RSA',
      n: expect.toBeString(),
      e: expect.toBeString(),
      d: expect.toBeString(),
      p: expect.toBeString(),
      q: expect.toBeString(),
      dp: expect.toBeString(),
      dq: expect.toBeString(),
      qi: expect.toBeString(),
    });
  });

  it('should generate an octet sequence json web key.', async () => {
    let jwk!: OCTJsonWebKey;

    expect((jwk = await generateJsonWebKey('oct', { length: 32 }))).toBeInstanceOf(OCTJsonWebKey);

    expect(jwk).toMatchObject<OCTJsonWebKeyParameters>({
      kty: 'oct',
      k: expect.toBeString(),
    });
  });
});
