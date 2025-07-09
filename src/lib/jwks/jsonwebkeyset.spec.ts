import { Buffer } from 'buffer';

import { JsonWebKeyNotFoundException } from '../exceptions/jsonwebkey-not-found.exception';
import { EcJwkParameters } from '../jwa/jwk/ec/ec-jwk.parameters';
import { RsaJwkParameters } from '../jwa/jwk/rsa/rsa-jwk.parameters';
import { JsonWebKey } from '../jwk/jsonwebkey';
import { JsonWebKeySet } from './jsonwebkeyset';
import { JwksParameters } from './jwks.parameters';

const publicEcJwkParameters: EcJwkParameters = {
  kty: 'EC',
  crv: 'P-256',
  x: '4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og',
  y: 'mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8',
};

const privateEcJwkParameters: EcJwkParameters = {
  ...publicEcJwkParameters,
  d: 'bwVX6Vx-TOfGKYOPAcu2xhaj3JUzs-McsC-suaHnFBo',
};

const publicRsaJwkParameters: RsaJwkParameters = {
  kty: 'RSA',
  n:
    'xjpFydzTbByzL5jhEa2yQO63dpS9d9SKaN107AR69skKiTR4uK1c4SzDt4YcurDB' +
    'yhgKNzeBo6Vq3IRrkrltp97LKWfeZdM-leGt8-UTZEWqrNf3UGOEj8kI6lbjiG-S' +
    'n_yNHcVA9qBV22norZkgXctHLeFbY6TmpD-I8_UiplZUHoc9KlYc7crCQRa-O7tK' +
    'FDULNTMjjifc0dmuYP7ZcYAZXmRmoOpQuDr8s7OZY7TAqN0btMfA7RpUCWLT6TMR' +
    'QPX8GcyTxfbkOrSTFueKMHVNdXDtl068XXJ9mkjORiEmwlzqSBoxdeLWcNf_u20S' +
    '5JG5iK0nsm1uZYu-02XN-w',
  e: 'AQAB',
};

const privateRsaJwkParameters: RsaJwkParameters = {
  ...publicRsaJwkParameters,
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

const invalidParametersOrKeys: any[] = [
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
  [undefined],
  [null],
  [true],
  [1],
  [1.2],
  [1n],
  ['a'],
  [Symbol('a')],
  [Buffer],
  [Buffer.alloc(1)],
  [() => 1],
  [[]],
  [{}],
  {},
  { keys: undefined },
  { keys: null },
  { keys: true },
  { keys: 1 },
  { keys: 1.2 },
  { keys: 1n },
  { keys: 'a' },
  { keys: Symbol('a') },
  { keys: Buffer },
  { keys: Buffer.alloc(1) },
  { keys: () => 1 },
  { keys: {} },
  { keys: [undefined] },
  { keys: [null] },
  { keys: [true] },
  { keys: [1] },
  { keys: [1.2] },
  { keys: [1n] },
  { keys: ['a'] },
  { keys: [Symbol('a')] },
  { keys: [Buffer] },
  { keys: [Buffer.alloc(1)] },
  { keys: [() => 1] },
  { keys: [[]] },
  { keys: [{}] },
  { keys: [{ kty: undefined }] },
  { keys: [{ kty: null }] },
  { keys: [{ kty: true }] },
  { keys: [{ kty: 1 }] },
  { keys: [{ kty: 1.2 }] },
  { keys: [{ kty: 1n }] },
  { keys: [{ kty: Symbol('a') }] },
  { keys: [{ kty: Buffer }] },
  { keys: [{ kty: Buffer.alloc(1) }] },
  { keys: [{ kty: () => 1 }] },
  { keys: [{ kty: {} }] },
  { keys: [{ kty: [] }] },
  { keys: [{ kty: 'unknown' }] },
];

const invalidJwksParameters: any[] = [
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
  { keys: undefined },
  { keys: null },
  { keys: true },
  { keys: 1 },
  { keys: 1.2 },
  { keys: 1n },
  { keys: 'a' },
  { keys: Symbol('a') },
  { keys: Buffer },
  { keys: Buffer.alloc(1) },
  { keys: () => 1 },
  { keys: {} },
  { keys: [undefined] },
  { keys: [null] },
  { keys: [true] },
  { keys: [1] },
  { keys: [1.2] },
  { keys: [1n] },
  { keys: ['a'] },
  { keys: [Symbol('a')] },
  { keys: [Buffer] },
  { keys: [Buffer.alloc(1)] },
  { keys: [() => 1] },
  { keys: [[]] },
  { keys: [{}] },
  { keys: [{ kty: undefined }] },
  { keys: [{ kty: null }] },
  { keys: [{ kty: true }] },
  { keys: [{ kty: 1 }] },
  { keys: [{ kty: 1.2 }] },
  { keys: [{ kty: 1n }] },
  { keys: [{ kty: Symbol('a') }] },
  { keys: [{ kty: Buffer }] },
  { keys: [{ kty: Buffer.alloc(1) }] },
  { keys: [{ kty: () => 1 }] },
  { keys: [{ kty: {} }] },
  { keys: [{ kty: [] }] },
  { keys: [{ kty: 'unknown' }] },
];

describe('JSON Web Key Set', () => {
  describe('constructor', () => {
    it.each(invalidParametersOrKeys)('should throw when the provided data is invalid.', (parametersOrKeys) => {
      expect(() => new JsonWebKeySet(parametersOrKeys)).toThrowWithMessage(
        TypeError,
        'Invalid argument "parametersOrKeys".',
      );
    });

    it('should create a json web key set with no json web keys.', () => {
      let jwkSet!: JsonWebKeySet;

      expect(() => (jwkSet = new JsonWebKeySet())).not.toThrow();
      expect(jwkSet.keys).toBeArrayOfSize(0);
    });

    it('should create a json web key set with the provided json web keys.', () => {
      let jwkSet!: JsonWebKeySet;

      const jwks = [new JsonWebKey(privateEcJwkParameters), new JsonWebKey(privateRsaJwkParameters)];

      expect(() => (jwkSet = new JsonWebKeySet(jwks))).not.toThrow();
      expect(jwkSet.keys).toBeArrayOfSize(2);
      expect(jwkSet.keys).toStrictEqual([expect.any(JsonWebKey), expect.any(JsonWebKey)]);
      expect(jwkSet.keys.map((key) => key.parameters)).toStrictEqual([privateEcJwkParameters, privateRsaJwkParameters]);
    });

    it('should create a json web key set with the json web keys in the provided json web key set parameters.', () => {
      let jwkSet!: JsonWebKeySet;

      const jwksParameters: JwksParameters = {
        keys: [privateEcJwkParameters, privateRsaJwkParameters],
      };

      expect(() => (jwkSet = new JsonWebKeySet(jwksParameters))).not.toThrow();
      expect(jwkSet.keys).toBeArrayOfSize(2);
      expect(jwkSet.keys).toStrictEqual([expect.any(JsonWebKey), expect.any(JsonWebKey)]);
      expect(jwkSet.keys.map((key) => key.parameters)).toStrictEqual([privateEcJwkParameters, privateRsaJwkParameters]);
    });
  });

  describe('isJwks()', () => {
    it.each(invalidJwksParameters)(
      'should return false when the provided data is not a valid jwks parameters object.',
      (data) => {
        expect(JsonWebKeySet.isJwks(data)).toBeFalse();
      },
    );

    it('should return true when the provided data is a valid jwks parameters object.', () => {
      expect(JsonWebKeySet.isJwks({ keys: [{ kty: 'RSA' }] })).toBeTrue();
    });
  });

  describe('find()', () => {
    const jwks = new JsonWebKeySet([
      new JsonWebKey({ ...publicEcJwkParameters, kid: 'ec-key', use: 'sig' }),
      new JsonWebKey({ ...publicRsaJwkParameters, kid: 'rsa-key', key_ops: ['encrypt'] }),
    ]);

    it('should return null when no json web key matches the provided predicate.', () => {
      expect(jwks.find((key) => key.parameters.kid === 'unknown')).toBeNull();
    });

    it('should return the json web key that matches the provided predicate.', () => {
      expect(jwks.find((key) => key.parameters.kid === 'ec-key')).toStrictEqual(jwks.keys[0]!);
      expect(jwks.find((key) => key.parameters.key_ops?.includes('encrypt') ?? false)).toStrictEqual(jwks.keys[1]!);
    });
  });

  describe('get()', () => {
    const jwkSet = new JsonWebKeySet([
      new JsonWebKey({ ...publicEcJwkParameters, kid: 'ec-key', use: 'sig' }),
      new JsonWebKey({ ...publicRsaJwkParameters, kid: 'rsa-key', key_ops: ['encrypt'] }),
    ]);

    it('should throw when no json web key matches the provided predicate.', () => {
      expect(() => jwkSet.get((key) => key.parameters.kid === 'unknown')).toThrow(JsonWebKeyNotFoundException);
    });

    it('should return the json web key that matches the provided predicate.', () => {
      expect(jwkSet.get((key) => key.parameters.kid === 'ec-key')).toStrictEqual(jwkSet.keys[0]!);
      expect(jwkSet.get((key) => key.parameters.key_ops?.includes('encrypt') ?? false)).toStrictEqual(jwkSet.keys[1]!);
    });
  });

  describe('toJSON()', () => {
    it('should return the parameters of the public json web keys.', () => {
      const jwkSet = new JsonWebKeySet([
        new JsonWebKey({ ...publicEcJwkParameters, kid: 'ec-key', use: 'sig' }),
        new JsonWebKey({ ...publicRsaJwkParameters, kid: 'rsa-key', use: 'sig' }),
      ]);

      expect(jwkSet.toJSON()).toStrictEqual<JwksParameters>({
        keys: [
          { ...publicEcJwkParameters, kid: 'ec-key', use: 'sig' },
          { ...publicRsaJwkParameters, kid: 'rsa-key', use: 'sig' },
        ],
      });

      expect(jwkSet.toJSON(true)).toStrictEqual<JwksParameters>({
        keys: [
          { ...publicEcJwkParameters, kid: 'ec-key', use: 'sig' },
          { ...publicRsaJwkParameters, kid: 'rsa-key', use: 'sig' },
        ],
      });
    });

    it('should return the parameters of the private json web keys.', () => {
      const jwkSet = new JsonWebKeySet([
        new JsonWebKey({ ...privateEcJwkParameters, kid: 'ec-key', use: 'sig' }),
        new JsonWebKey({ ...privateRsaJwkParameters, kid: 'rsa-key', use: 'sig' }),
      ]);

      expect(jwkSet.toJSON()).toStrictEqual<JwksParameters>({
        keys: [
          { ...publicEcJwkParameters, kid: 'ec-key', use: 'sig' },
          { ...publicRsaJwkParameters, kid: 'rsa-key', use: 'sig' },
        ],
      });

      expect(jwkSet.toJSON(true)).toStrictEqual<JwksParameters>({
        keys: [
          { ...privateEcJwkParameters, kid: 'ec-key', use: 'sig' },
          { ...privateRsaJwkParameters, kid: 'rsa-key', use: 'sig' },
        ],
      });
    });
  });
});
