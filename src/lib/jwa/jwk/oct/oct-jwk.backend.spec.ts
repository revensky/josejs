import { Buffer } from 'buffer';

import { InvalidJsonWebKeyException } from '../../../exceptions/invalid-jsonwebkey.exception';
import { OctJwkBackend } from './oct-jwk.backend';
import { OctJwkParameters } from './oct-jwk.parameters';

const parameters: OctJwkParameters = {
  kty: 'oct',
  k: 'qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ',
};

const invalidKtys: any[] = [
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

const invalidKs: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, [], ''];

describe('Octet Sequence JSON Web Key Backend', () => {
  const backend = new OctJwkBackend();

  describe('validate()', () => {
    it.each(invalidKtys)('should throw when the provided "kty" is invalid.', (kty) => {
      expect(() => backend.validate({ ...parameters, kty })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "kty".',
      );
    });

    it.each(invalidKs)('should throw when the provided "k" is invalid.', (k) => {
      expect(() => backend.validate({ ...parameters, k })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "k".',
      );
    });

    it('should not throw when providing a valid json web key parameters object.', () => {
      expect(() => backend.validate(parameters)).not.toThrow();
    });
  });

  describe('getThumbprintParameters()', () => {
    it('should return the parameters "k" and "kty" in this exact order.', () => {
      const thumbprintParameters = backend.getThumbprintParameters(parameters);

      expect(Object.entries(thumbprintParameters)).toStrictEqual<[string, string][]>([
        ['k', parameters.k],
        ['kty', parameters.kty],
      ]);
    });
  });

  describe('getPrivateParameters()', () => {
    it('should return an empty list.', () => {
      expect(backend.getPrivateParameters()).toStrictEqual([]);
    });
  });
});
