import https from 'https';
import Stream from 'stream';

import { InvalidJsonWebKeyException } from '../exceptions/invalid-jsonwebkey.exception';
import { JwkParameters } from '../jwk/jwk.parameters';
import { validateX509CertificateParameters } from './validate-x509-certificate-parameters';

jest.mock('https', () => jest.requireActual<typeof https>('https'));

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

describe('validateX509CertificateParameters()', () => {
  it('should throw when providing both the parameters "x5u" and "x5c".', () => {
    expect(() => validateX509CertificateParameters(parameters, { x5u: 'x5u', x5c: ['x5c'] })).toThrowWithMessage(
      InvalidJsonWebKeyException,
      'The parameters "x5u" and "x5c" cannot be used together.',
    );
  });

  it('should throw when providing both the parameters "x5t" and "x5t#S256" but none of the parameters "x5u" or "x5c".', () => {
    expect(() => {
      return validateX509CertificateParameters(parameters, {
        x5t: '3Z_9ZZrl56P-qMF-OfBNvG88Vgk',
        'x5t#S256': 'Yme6YpM7-Ugr84cJCoBpC4lXJeelS4uvoUbdiEDwgL8',
      });
    }).toThrowWithMessage(
      InvalidJsonWebKeyException,
      'The parameters "x5t" and "x5t#S256" require one of "x5u" or "x5c".',
    );
  });

  it('should throw when providing the parameter "x5t" but none of the parameters "x5u" or "x5c".', () => {
    expect(() =>
      validateX509CertificateParameters(parameters, { x5t: '3Z_9ZZrl56P-qMF-OfBNvG88Vgk' }),
    ).toThrowWithMessage(InvalidJsonWebKeyException, 'The parameter "x5t" requires one of "x5u" or "x5c".');
  });

  it('should throw when providing the parameter "x5t#S256" but none of the parameters "x5u" or "x5c".', () => {
    expect(() => {
      return validateX509CertificateParameters(parameters, {
        'x5t#S256': 'Yme6YpM7-Ugr84cJCoBpC4lXJeelS4uvoUbdiEDwgL8',
      });
    }).toThrowWithMessage(InvalidJsonWebKeyException, 'The parameter "x5t#S256" requires one of "x5u" or "x5c".');
  });

  it('should throw when the parameter "x5u" returns an invalid certificate chain.', () => {
    const stream = new Stream();
    https.get = jest.fn().mockImplementationOnce((_url, callback) => {
      callback(stream);
      stream.emit('data', '');
      stream.emit('end');
    });

    expect(() => validateX509CertificateParameters(parameters, { x5u: 'https://localhost' })).toThrowWithMessage(
      InvalidJsonWebKeyException,
      'The parameter "x5u" contains an invalid certificate.',
    );
  });

  it('should throw when the parameter "x5c" returns an invalid certificate chain.', () => {
    expect(() => validateX509CertificateParameters(parameters, { x5c: [''] })).toThrowWithMessage(
      InvalidJsonWebKeyException,
      'The parameter "x5c" contains an invalid certificate.',
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

    expect(() => validateX509CertificateParameters(parameters, { x5u: 'https://localhost' })).toThrowWithMessage(
      InvalidJsonWebKeyException,
      'The provided certificate is not yet valid.',
    );

    jest.useRealTimers();
  });

  it('should throw when a certificate is expired.', () => {
    jest.useFakeTimers().setSystemTime(new Date(2100, 0, 1));

    expect(() => validateX509CertificateParameters(parameters, { x5c: [pemCertificate] })).toThrowWithMessage(
      InvalidJsonWebKeyException,
      'The provided certificate is expired.',
    );

    jest.useRealTimers();
  });

  it('should throw when the was not signed by the certificate.', () => {
    jest.useFakeTimers().setSystemTime(new Date(2021, 0, 1));

    expect(() =>
      validateX509CertificateParameters({ ...parameters, e: 'AQAJ' }, { x5c: [pemCertificate] }),
    ).toThrowWithMessage(InvalidJsonWebKeyException, 'The provided certificate did not sign the json web key.');

    jest.useRealTimers();
  });

  it('should throw when the sha-1 fingerprint does not match the provided "x5t".', () => {
    jest.useFakeTimers().setSystemTime(new Date(2021, 0, 1));

    expect(() => {
      return validateX509CertificateParameters(parameters, {
        x5c: [pemCertificate],
        x5t: '3Z_9ZZrl56P-qMF-OfBNvG88Vgz',
      });
    }).toThrowWithMessage(
      InvalidJsonWebKeyException,
      'The certificate\'s SHA-1 Fingerprint does not match the value at "x5t".',
    );

    jest.useRealTimers();
  });

  it('should throw when the sha-256 fingerprint does not match the provided "x5t#S256".', () => {
    jest.useFakeTimers().setSystemTime(new Date(2021, 0, 1));

    expect(() => {
      return validateX509CertificateParameters(parameters, {
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

    expect(() =>
      validateX509CertificateParameters(parameters, { x5c: [pemCertificate, pemCertificate] }),
    ).toThrowWithMessage(InvalidJsonWebKeyException, 'A certificate in the chain was not successfully verified.');

    jest.useRealTimers();
  });
});
