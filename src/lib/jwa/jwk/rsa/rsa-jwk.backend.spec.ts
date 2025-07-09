import { Buffer } from 'buffer';

import { InvalidJsonWebKeyException } from '../../../exceptions/invalid-jsonwebkey.exception';
import { RsaJwkBackend } from './rsa-jwk.backend';
import { RsaJwkParameters } from './rsa-jwk.parameters';

const parameters: RsaJwkParameters = {
  kty: 'RSA',
  n:
    'xjpFydzTbByzL5jhEa2yQO63dpS9d9SKaN107AR69skKiTR4uK1c4SzDt4YcurDB' +
    'yhgKNzeBo6Vq3IRrkrltp97LKWfeZdM-leGt8-UTZEWqrNf3UGOEj8kI6lbjiG-S' +
    'n_yNHcVA9qBV22norZkgXctHLeFbY6TmpD-I8_UiplZUHoc9KlYc7crCQRa-O7tK' +
    'FDULNTMjjifc0dmuYP7ZcYAZXmRmoOpQuDr8s7OZY7TAqN0btMfA7RpUCWLT6TMR' +
    'QPX8GcyTxfbkOrSTFueKMHVNdXDtl068XXJ9mkjORiEmwlzqSBoxdeLWcNf_u20S' +
    '5JG5iK0nsm1uZYu-02XN-w',
  e: 'AQAB',
  d:
    'cc2YrWia9LGRad0SMe0PrlmeeHSyRe5-u--QJcP4uF_5LYYzXIsjDJ9_iYh0S_YY' +
    'e6bLjqHOSp44OHvJqoXMX5j3-ECKnNjnUHMtRB2awXGBqBOhB8TqoQXgmXDi1jx_' +
    '6Fu8xH-vaSfpwrsN-0QzIcYHil6b8hwE0f0r6istBmL7iayJbnONp7na9ow2fUQl' +
    'nr41vsHZa4knTZ2E2kq5ntgaXlF6AIdc4DD_BZpf2alEbhQMX9T168ZsSyAs7wKS' +
    'd3ivhHRQayXEapUfZ_ykvnF4-DoVI1iRoowgZ-dlnv4Ff3YrKQ3Zv3uHJcF1BtWQ' +
    'VipOIHx4GyIc4bmTSA5PEQ',
  p:
    '-ZFuDg38cG-e5L6h1Jbn8ngifWgHx8m1gybkY7yEpU1V02fvQAMI1XG-1WpZm2xj' +
    'j218wNCj0BCEdmdBqZMk5RlzLagtfzQ3rPO-ucYPZ_SDmy8Udzr-sZLCqMFyLtxk' +
    'gMfGo4QZ6UJWYpTCCmZ92nS_pa4ePrQdlpnS4DLv_SM',
  q:
    'y1YdZtsbYfCOdsYBZrDpcvubwMN2fKRAzETYW5sqYv8XkxHG1J1zHH-zWJBQfZhT' +
    'biHPgHvoaFykEm9xhuA77RFGRXxFUrGBtfqIx_OG-kRWudmH83EyMzMoKQaW98RX' +
    'WqRO1JDlcs4_vzf_KN63zQKv5i4UdiiObQkZCYIOVUk',
  dp:
    'vqtDX-2DjgtZY_3Y-eiJMRBjmVgfiZ4r1RWjrCddWEVrauafPVKULy6F09s6tqnq' +
    'rqvBgjZk0ROtgCCHZB0NNRNqkdlJWUP1vWdDsf8FyjBfU_J2OlmSOOydV_zjVbX_' +
    '-vumYUsN2M5b3Vk1nmiLgplryhLq_JDzghnnqG6CN-0',
  dq:
    'tKczxBhSwbcpu5i70fLH1iJ5BNAkSyTbdSCNYQYAqKee2Elo76lbhixmuP6upIdb' +
    'SHO9mZd8qov0MXTV1lEOrNc2KbH5HTkb1wRZ1dwlReDFdKUxxjYBtb9zpM93_XVx' +
    'btSgPPbnBBL-S_OCPVtyzS_f-49hGoF52KHGns3v0hE',
  qi:
    'C4q9uIi-1fYhE0NTWVNzdhSi7fA3uznTWaW1X5LWBF4gBOcWvMMTfOZEaPjtY2WP' +
    'XaTWU4bdVN0GgktVLUDPLrSj533W1cOQZb_mm_7BFNrleelruT87bZhWPYQ979kl' +
    '6590ySgbH81pEM8FQW1JBATz0MYtUNZAt8N360vayE4',
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

const invalidNs: any[] = [
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
  'cafebabe',
];

const invalidEs: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidDs: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidPs: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidQs: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidDPs: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidDQs: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidQIs: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];

describe('RSA JSON Web Key Backend', () => {
  const backend = new RsaJwkBackend();

  describe('validate()', () => {
    it.each(invalidKtys)('should throw when the provided "kty" is invalid.', (kty) => {
      expect(() => backend.validate({ ...parameters, kty })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "kty".',
      );
    });

    it.each(invalidNs)('should throw when the provided "n" is invalid.', (n) => {
      expect(() => backend.validate({ ...parameters, n })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "n".',
      );
    });

    it.each(invalidEs)('should throw when the provided "e" is invalid.', (e) => {
      expect(() => backend.validate({ ...parameters, e })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "e".',
      );
    });

    it.each(invalidDs)('should throw when the provided "d" is invalid.', (d) => {
      expect(() => backend.validate({ ...parameters, d })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "d".',
      );
    });

    it.each(invalidPs)('should throw when the provided "p" is invalid.', (p) => {
      expect(() => backend.validate({ ...parameters, p })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "p".',
      );
    });

    it.each(invalidQs)('should throw when the provided "q" is invalid.', (q) => {
      expect(() => backend.validate({ ...parameters, q })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "q".',
      );
    });

    it.each(invalidDPs)('should throw when the provided "dp" is invalid.', (dp) => {
      expect(() => backend.validate({ ...parameters, dp })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "dp".',
      );
    });

    it.each(invalidDQs)('should throw when the provided "dq" is invalid.', (dq) => {
      expect(() => backend.validate({ ...parameters, dq })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "dq".',
      );
    });

    it.each(invalidQIs)('should throw when the provided "qi" is invalid.', (qi) => {
      expect(() => backend.validate({ ...parameters, qi })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "qi".',
      );
    });

    it('should not throw when providing a valid json web key parameters object.', () => {
      expect(() => backend.validate(parameters)).not.toThrow();
    });
  });

  describe('getThumbprintParameters()', () => {
    it('should return the parameters "e", "kty" and "n" in this exact order.', () => {
      const thumbprintParameters = backend.getThumbprintParameters(parameters);

      expect(Object.entries(thumbprintParameters)).toStrictEqual<[string, string][]>([
        ['e', parameters.e],
        ['kty', parameters.kty],
        ['n', parameters.n],
      ]);
    });
  });

  describe('getPrivateParameters()', () => {
    it('should return the parameters "d", "p", "q", "dp", "dq", "qi".', () => {
      expect(backend.getPrivateParameters()).toStrictEqual(['d', 'p', 'q', 'dp', 'dq', 'qi']);
    });
  });
});
