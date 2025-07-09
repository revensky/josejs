import { Buffer } from 'buffer';
import https from 'https';
import Stream from 'stream';

import { InvalidJsonWebKeyException } from '../exceptions/invalid-jsonwebkey.exception';
import { EcJwkBackend } from '../jwa/jwk/ec/ec-jwk.backend';
import { EcJwkParameters } from '../jwa/jwk/ec/ec-jwk.parameters';
import { JwkBackend } from '../jwa/jwk/jwk.backend';
import { OctJwkBackend } from '../jwa/jwk/oct/oct-jwk.backend';
import { OctJwkParameters } from '../jwa/jwk/oct/oct-jwk.parameters';
import { OkpJwkBackend } from '../jwa/jwk/okp/okp-jwk.backend';
import { RsaJwkBackend } from '../jwa/jwk/rsa/rsa-jwk.backend';
import { JsonWebKey } from './jsonwebkey';
import { JwkKeyOp } from './jwk.key-op';
import { JwkKty } from './jwk.kty';
import { JwkParameters } from './jwk.parameters';
import { JwkUse } from './jwk.use';

const x509Certificate: string = `-----BEGIN CERTIFICATE-----
MIIH/TCCBeWgAwIBAgIQaBYE3/M08XHYCnNVmcFBcjANBgkqhkiG9w0BAQsFADBy
MQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0b24x
ETAPBgNVBAoMCFNTTCBDb3JwMS4wLAYDVQQDDCVTU0wuY29tIEVWIFNTTCBJbnRl
cm1lZGlhdGUgQ0EgUlNBIFIzMB4XDTIwMDQwMTAwNTgzM1oXDTIxMDcxNjAwNTgz
M1owgb0xCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91
c3RvbjERMA8GA1UECgwIU1NMIENvcnAxFjAUBgNVBAUTDU5WMjAwODE2MTQyNDMx
FDASBgNVBAMMC3d3dy5zc2wuY29tMR0wGwYDVQQPDBRQcml2YXRlIE9yZ2FuaXph
dGlvbjEXMBUGCysGAQQBgjc8AgECDAZOZXZhZGExEzARBgsrBgEEAYI3PAIBAxMC
VVMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDHheRkbb1FCc7xRKst
wK0JIGaKY8t7JbS2bQ2b6YIJDgnHuIYHqBrCUV79oelikkokRkFvcvpaKinFHDQH
UpWEI6RUERYmSCg3O8Wi42uOcV2B5ZabmXCkwdxY5Ecl51BbM8UnGdoAGbdNmiRm
SmTjcs+lhMxg4fFY6lBpiEVFiGUjGRR+61R67Lz6U4KJeLNcCm07QwFYKBmpi08g
dygSvRdUw55Jopredj+VGtjUkB4hFT4GQX/ght69Rlqz/+8u0dEQkhuUuucrqalm
SGy43HRwBfDKFwYeWM7CPMd5e/dO+t08t8PbjzVTTv5hQDCsEYIV2T7AFI9ScNxM
kh7/AgMBAAGjggNBMIIDPTAfBgNVHSMEGDAWgBS/wVqH/yj6QT39t0/kHa+gYVgp
vTB/BggrBgEFBQcBAQRzMHEwTQYIKwYBBQUHMAKGQWh0dHA6Ly93d3cuc3NsLmNv
bS9yZXBvc2l0b3J5L1NTTGNvbS1TdWJDQS1FVi1TU0wtUlNBLTQwOTYtUjMuY3J0
MCAGCCsGAQUFBzABhhRodHRwOi8vb2NzcHMuc3NsLmNvbTAfBgNVHREEGDAWggt3
d3cuc3NsLmNvbYIHc3NsLmNvbTBfBgNVHSAEWDBWMAcGBWeBDAEBMA0GCyqEaAGG
9ncCBQEBMDwGDCsGAQQBgqkwAQMBBDAsMCoGCCsGAQUFBwIBFh5odHRwczovL3d3
dy5zc2wuY29tL3JlcG9zaXRvcnkwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUF
BwMBMEgGA1UdHwRBMD8wPaA7oDmGN2h0dHA6Ly9jcmxzLnNzbC5jb20vU1NMY29t
LVN1YkNBLUVWLVNTTC1SU0EtNDA5Ni1SMy5jcmwwHQYDVR0OBBYEFADAFUIazw5r
ZIHapnRxIUnpw+GLMA4GA1UdDwEB/wQEAwIFoDCCAX0GCisGAQQB1nkCBAIEggFt
BIIBaQFnAHcA9lyUL9F3MCIUVBgIMJRWjuNNExkzv98MLyALzE7xZOMAAAFxM0ho
bwAABAMASDBGAiEA6xeliNR8Gk/63pYdnS/vOx/CjptEMEv89WWh1/urWIECIQDy
BreHU25DzwukQaRQjwW655ZLkqCnxbxQWRiOemj9JAB1AJQgvB6O1Y1siHMfgosi
LA3R2k1ebE+UPWHbTi9YTaLCAAABcTNIaNwAAAQDAEYwRAIgGRE4wzabNRdD8kq/
vFP3tQe2hm0x5nXulowh4Ibw3lkCIFYb/3lSDplS7AcR4r+XpWtEKSTFWJmNCRbc
XJur2RGBAHUA7sCV7o1yZA+S48O5G8cSo2lqCXtLahoUOOZHssvtxfkAAAFxM0ho
8wAABAMARjBEAiB6IvboWss3R4ItVwjebl7D3yoFaX0NDh2dWhhgwCxrHwIgCfq7
ocMC5t+1ji5M5xaLmPC4I+WX3I/ARkWSyiO7IQcwDQYJKoZIhvcNAQELBQADggIB
ACeuur4QnujqmguSrHU3mhf+cJodzTQNqo4tde+PD1/eFdYAELu8xF+0At7xJiPY
i5RKwilyP56v+3iY2T9lw7S8TJ041VLhaIKp14MzSUzRyeoOAsJ7QADMClHKUDlH
UU2pNuo88Y6igovT3bsnwJNiEQNqymSSYhktw0taduoqjqXn06gsVioWTVDXysd5
qEx4t6sIgIcMm26YH1vJpCQEhKpc2y07gRkklBZRtMjThv4cXyyMX7uTcdT7AJBP
ueifCoV25JxXuo8d5139gwP1BAe7IBVPx2u7KN/UyOXdZmwMf/TmFGwDdCfsyHf/
ZsB2wLHozTYoAVmQ9FoU1JLgcVivqJ+vNlBhHXhlxMdN0j80R9Nz6EIglQjeK3O8
I/cFGm/B8+42hOlCId9ZdtndJcRJVji0wD0qwevCafA9jJlHv/jsE+I9Uz6cpCyh
sw+lrFdxUgqU58axqeK89FR+No4q0IIO+Ji1rJKr9nkSB0BqXozVnE1YB/KLvdIs
uYZJuqb2pKku+zzT6gUwHUTZvBiNOtXL4Nxwc/KT7WzOSd2wP10QI8DKg4vfiNDs
HWmB1c4Kji6gOgA5uSUzaGmq/v4VncK5Ur+n9LbfnfLc28J5ft/GotinMyDk3iar
F10YlqcOmeX1uFmKbdi/XorGlkCoMF3TDx8rmp9DBiB/
-----END CERTIFICATE-----`;

const pemCertificate = x509Certificate.replaceAll(/-----\w+ CERTIFICATE-----/g, '');

jest.mock('https', () => jest.requireActual<typeof https>('https'));

const parameters: JwkParameters = {
  kty: 'RSA',
  n:
    'x4XkZG29RQnO8USrLcCtCSBmimPLeyW0tm0Nm-mCCQ4Jx7iGB6gawlFe_aHpYpJK' +
    'JEZBb3L6WiopxRw0B1KVhCOkVBEWJkgoNzvFouNrjnFdgeWWm5lwpMHcWORHJedQ' +
    'WzPFJxnaABm3TZokZkpk43LPpYTMYOHxWOpQaYhFRYhlIxkUfutUeuy8-lOCiXiz' +
    'XAptO0MBWCgZqYtPIHcoEr0XVMOeSaKa3nY_lRrY1JAeIRU-BkF_4IbevUZas__v' +
    'LtHREJIblLrnK6mpZkhsuNx0cAXwyhcGHljOwjzHeXv3TvrdPLfD2481U07-YUAw' +
    'rBGCFdk-wBSPUnDcTJIe_w',
  e: 'AQAB',
};

const invalidJwkParameters: any[] = [
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
];

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

const invalidUses: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, [], 'unknown'];

const invalidKeyOps: any[] = [
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
  {},
  [],
  [undefined],
  [null],
  [true],
  [1],
  [1.2],
  [1n],
  [Symbol('a')],
  [Buffer],
  [Buffer.alloc(1)],
  [() => 1],
  [{}],
  [[]],
  ['unknown'],
  ['sign', 'verify', 'sign'],
];

const invalidAlgs: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, [], 'unknown'];
const invalidKids: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidX5Us: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];

const invalidX5Cs: any[] = [
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
  {},
  [],
  [undefined],
  [null],
  [true],
  [1],
  [1.2],
  [1n],
  [Symbol('a')],
  [Buffer],
  [Buffer.alloc(1)],
  [() => 1],
  [{}],
  [[]],
];

const invalidX5Ts: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidX5TS256s: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];

const invalidUseKeyOps: [JwkUse, JwkKeyOp[]][] = [
  ['enc', ['sign']],
  ['enc', ['verify']],
  ['enc', ['decrypt', 'sign']],
  ['sig', ['decrypt']],
  ['sig', ['encrypt']],
  ['sig', ['unwrapKey']],
  ['sig', ['wrapKey']],
  ['sig', ['sign', 'decrypt']],
];

describe('JSON Web Key', () => {
  describe('backends', () => {
    it('should have all supported json web key backends.', () => {
      expect(JsonWebKey['backends']).toStrictEqual<Record<JwkKty, JwkBackend>>({
        EC: expect.any(EcJwkBackend),
        OKP: expect.any(OkpJwkBackend),
        RSA: expect.any(RsaJwkBackend),
        oct: expect.any(OctJwkBackend),
      });
    });
  });

  describe('jwkUses', () => {
    it('should have all supported json web key public key uses.', () => {
      expect(JsonWebKey['jwkUses']).toStrictEqual<JwkUse[]>(['enc', 'sig']);
    });
  });

  describe('jwkKeyOps', () => {
    it('should have all supported json web key key operations.', () => {
      expect(JsonWebKey['jwkKeyOps']).toStrictEqual<JwkKeyOp[]>([
        'decrypt',
        'deriveBits',
        'deriveKey',
        'encrypt',
        'sign',
        'unwrapKey',
        'verify',
        'wrapKey',
      ]);
    });
  });

  describe('constructor', () => {
    it.each(invalidKtys)('should throw when the provided "kty" is invalid.', (kty) => {
      expect(() => new JsonWebKey({ ...parameters, kty })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "kty".',
      );
    });

    it.each(invalidUses)('should throw when the provided "use" is invalid.', (use) => {
      expect(() => new JsonWebKey({ ...parameters, use })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "use".',
      );
    });

    it.each(invalidKeyOps)('should throw when the provided "key_ops" is invalid.', (keyOps) => {
      expect(() => new JsonWebKey({ ...parameters, key_ops: keyOps })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "key_ops".',
      );
    });

    it.each(invalidAlgs)('should throw when the provided "alg" is invalid.', (alg) => {
      expect(() => new JsonWebKey({ ...parameters, alg })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "alg".',
      );
    });

    it.each(invalidKids)('should throw when the provided "kid" is invalid.', (kid) => {
      expect(() => new JsonWebKey({ ...parameters, kid })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "kid".',
      );
    });

    it.each(invalidX5Us)('should throw when the provided "x5u" is invalid.', (x5u) => {
      expect(() => new JsonWebKey({ ...parameters, x5u })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "x5u".',
      );
    });

    it.each(invalidX5Cs)('should throw when the provided "x5c" is invalid.', (x5c) => {
      expect(() => new JsonWebKey({ ...parameters, x5c })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "x5c".',
      );
    });

    it.each(invalidX5Ts)('should throw when the provided "x5t" is invalid.', (x5t) => {
      expect(() => new JsonWebKey({ ...parameters, x5t })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "x5t".',
      );
    });

    it.each(invalidX5TS256s)('should throw when the provided "x5t#S256" is invalid.', (x5tS256) => {
      expect(() => new JsonWebKey({ ...parameters, 'x5t#S256': x5tS256 })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'Invalid json web key parameter "x5t#S256".',
      );
    });

    it.each(invalidUseKeyOps)(
      'should throw when providing an invalid combination of json web key parameters "use" and "key_ops".',
      (use, keyOps) => {
        expect(() => new JsonWebKey({ ...parameters, use, key_ops: keyOps })).toThrowWithMessage(
          InvalidJsonWebKeyException,
          'Invalid combination of json web key parameters "use" and "key_ops".',
        );
      },
    );

    it('should throw when providing both the parameters "x5u" and "x5c".', () => {
      expect(() => new JsonWebKey({ ...parameters, x5u: 'x5u', x5c: ['x5c'] })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'The parameters "x5u" and "x5c" cannot be used together.',
      );
    });

    it('should throw when providing both the parameters "x5t" and "x5t#S256" but none of the parameters "x5u" or "x5c".', () => {
      expect(() => {
        return new JsonWebKey({
          ...parameters,
          x5t: '3Z_9ZZrl56P-qMF-OfBNvG88Vgk',
          'x5t#S256': 'Yme6YpM7-Ugr84cJCoBpC4lXJeelS4uvoUbdiEDwgL8',
        });
      }).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'The parameters "x5t" and "x5t#S256" require one of "x5u" or "x5c".',
      );
    });

    it('should throw when providing the parameter "x5t" but none of the parameters "x5u" or "x5c".', () => {
      expect(() => new JsonWebKey({ ...parameters, x5t: '3Z_9ZZrl56P-qMF-OfBNvG88Vgk' })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'The parameter "x5t" requires one of "x5u" or "x5c".',
      );
    });

    it('should throw when providing the parameter "x5t#S256" but none of the parameters "x5u" or "x5c".', () => {
      expect(() => {
        return new JsonWebKey({ ...parameters, 'x5t#S256': 'Yme6YpM7-Ugr84cJCoBpC4lXJeelS4uvoUbdiEDwgL8' });
      }).toThrowWithMessage(InvalidJsonWebKeyException, 'The parameter "x5t#S256" requires one of "x5u" or "x5c".');
    });

    it('should throw when the parameter "x5u" returns an invalid certificate chain.', () => {
      const stream = new Stream();
      https.get = jest.fn().mockImplementationOnce((_url, callback) => {
        callback(stream);
        stream.emit('data', '');
        stream.emit('end');
      });

      expect(() => new JsonWebKey({ ...parameters, x5u: 'https://localhost' })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'The json web key parameter "x5u" contains an invalid certificate.',
      );
    });

    it('should throw when the parameter "x5c" returns an invalid certificate chain.', () => {
      expect(() => new JsonWebKey({ ...parameters, x5c: [''] })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'The json web key parameter "x5c" contains an invalid certificate.',
      );
    });

    it('should throw when a certificate is not yet valid.', () => {
      jest.useFakeTimers().setSystemTime(new Date(1900, 0, 1));

      const stream = new Stream();
      https.get = jest.fn().mockImplementationOnce((_url, callback) => {
        callback(stream);
        stream.emit('data', x509Certificate);
        stream.emit('end');
      });

      expect(() => new JsonWebKey({ ...parameters, x5u: 'https://localhost' })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'The provided certificate is not yet valid.',
      );

      jest.useRealTimers();
    });

    it('should throw when a certificate is expired.', () => {
      jest.useFakeTimers().setSystemTime(new Date(2100, 0, 1));

      expect(() => new JsonWebKey({ ...parameters, x5c: [pemCertificate] })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'The provided certificate is expired.',
      );

      jest.useRealTimers();
    });

    it('should throw when the json web key was not signed by the certificate.', () => {
      jest.useFakeTimers().setSystemTime(new Date(2021, 0, 1));

      expect(() => new JsonWebKey({ ...parameters, e: 'AQAJ', x5c: [pemCertificate] })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'The provided certificate did not sign the json web key.',
      );

      jest.useRealTimers();
    });

    it('should throw when the sha-1 fingerprint does not match the provided "x5t".', () => {
      jest.useFakeTimers().setSystemTime(new Date(2021, 0, 1));

      expect(() => {
        return new JsonWebKey({ ...parameters, x5c: [pemCertificate], x5t: '3Z_9ZZrl56P-qMF-OfBNvG88Vgz' });
      }).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'The certificate\'s SHA-1 Fingerprint does not match the value at "x5t".',
      );

      jest.useRealTimers();
    });

    it('should throw when the sha-256 fingerprint does not match the provided "x5t#S256".', () => {
      jest.useFakeTimers().setSystemTime(new Date(2021, 0, 1));

      expect(() => {
        return new JsonWebKey({
          ...parameters,
          x5c: [pemCertificate],
          'x5t#S256': 'Yme6YpM7-Ugr84cJCoBpC4lXJeelS4uvoUbdiEDwgLz',
        });
      }).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'The certificate\'s SHA-256 Fingerprint does not match the value at "x5t#S256".',
      );

      jest.useRealTimers();
    });

    it('should throw when a certificate in the chain was not signed by the following certificate.', () => {
      jest.useFakeTimers().setSystemTime(new Date(2021, 0, 1));

      expect(() => new JsonWebKey({ ...parameters, x5c: [pemCertificate, pemCertificate] })).toThrowWithMessage(
        InvalidJsonWebKeyException,
        'A certificate in the chain was not successfully verified.',
      );

      jest.useRealTimers();
    });

    it('should create an instance of a json web key.', () => {
      let jwk!: JsonWebKey;

      const jwkBackendValidate = jest.spyOn(RsaJwkBackend.prototype, 'validate');

      expect(() => (jwk = new JsonWebKey(parameters))).not.toThrow();

      expect(jwk).toBeInstanceOf(JsonWebKey);

      expect(jwk['backend']).toBeInstanceOf(RsaJwkBackend);
      expect(jwkBackendValidate).toHaveBeenCalledOnce();
      expect(jwkBackendValidate).toHaveBeenCalledWith(parameters);

      expect(jwk.parameters).toStrictEqual(parameters);
    });
  });

  describe('isJwk()', () => {
    it.each(invalidJwkParameters)('should return false when the provided data is not a plain object.', (data) => {
      expect(JsonWebKey.isJwk(data)).toBeFalse();
    });

    it('should return false when the provided data has no "kty" parameter.', () => {
      expect(JsonWebKey.isJwk({})).toBeFalse();
    });

    it.each(invalidKtys)('should return false when the provided data an invalid "kty" parameter.', (kty) => {
      expect(JsonWebKey.isJwk({ kty })).toBeFalse();
    });

    it('should return true when the provided data is a valid json web key parameters object.', () => {
      expect(JsonWebKey.isJwk({ kty: 'RSA' })).toBeTrue();
    });
  });

  describe('getThumbprint()', () => {
    it('should return the thumbprint of the json web key.', () => {
      expect(new JsonWebKey(parameters).getThumbprint('sha256').toString('base64url')).toEqual(
        '9xLGZzIbwEak5aeOAGPXdPLWR374N6ECJ91cNtw_qg8',
      );
    });
  });

  describe('toJSON()', () => {
    it('should return the parameters of a symmetric json web key.', () => {
      const jwkParameters: OctJwkParameters = {
        kty: 'oct',
        k: 'qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ',
      };

      const jwk = new JsonWebKey(jwkParameters);

      expect(jwk.toJSON()).toMatchObject(jwkParameters);
      expect(jwk.toJSON(true)).toMatchObject(jwkParameters);
    });

    it('should return the parameters of an asymmetric json web key.', () => {
      const publicJwkParameters: EcJwkParameters = {
        kty: 'EC',
        crv: 'P-256',
        x: '4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og',
        y: 'mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8',
      };

      const privateJwkParameters: EcJwkParameters = {
        ...publicJwkParameters,
        d: 'bwVX6Vx-TOfGKYOPAcu2xhaj3JUzs-McsC-suaHnFBo',
      };

      const publicJwk = new JsonWebKey(publicJwkParameters);
      const privateJwk = new JsonWebKey(privateJwkParameters);

      expect(publicJwk.toJSON()).toMatchObject(publicJwkParameters);
      expect(publicJwk.toJSON(true)).toMatchObject(publicJwkParameters);

      expect(privateJwk.toJSON()).toMatchObject(publicJwkParameters);
      expect(privateJwk.toJSON(true)).toMatchObject(privateJwkParameters);
    });
  });
});
