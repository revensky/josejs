import { X509Certificate } from 'crypto';
import https from 'https';

import { InvalidJsonWebKeyException } from '../exceptions/invalid-jsonwebkey.exception';
import { JwkParameters } from '../jwk/jwk.parameters';

interface X509Parameters {
  x5u?: string;
  x5c?: string[];
  x5t?: string;
  'x5t#S256'?: string;
}

/**
 * Checks if the provided X.509 Certificate Parameters are valid.
 *
 * @param parameters X.509 Certificate Parameters.
 */
export function validateX509CertificateParameters<T extends X509Parameters>(
  jwkParameters: JwkParameters,
  x509Parameters: T,
): void {
  // Cannot use both "x5u" and "x5c" parameters.
  if (typeof x509Parameters.x5u !== 'undefined' && typeof x509Parameters.x5c !== 'undefined') {
    throw new InvalidJsonWebKeyException('The parameters "x5u" and "x5c" cannot be used together.');
  }

  // Cannot not use "x5t" or "x5t#S256" anot not provide one of "x5u" or "x5c".
  if (typeof x509Parameters.x5u === 'undefined' && typeof x509Parameters.x5c === 'undefined') {
    if (typeof x509Parameters.x5t !== 'undefined' && typeof x509Parameters['x5t#S256'] !== 'undefined') {
      throw new InvalidJsonWebKeyException('The parameters "x5t" and "x5t#S256" require one of "x5u" or "x5c".');
    }

    if (typeof x509Parameters.x5t !== 'undefined') {
      throw new InvalidJsonWebKeyException('The parameter "x5t" requires one of "x5u" or "x5c".');
    }

    if (typeof x509Parameters['x5t#S256'] !== 'undefined') {
      throw new InvalidJsonWebKeyException('The parameter "x5t#S256" requires one of "x5u" or "x5c".');
    }
  }

  let x509CertificateChain!: X509Certificate[];

  if (typeof x509Parameters.x5u !== 'undefined') {
    x509CertificateChain = getX5UCertificateChain(x509Parameters.x5u);
  }

  if (typeof x509Parameters.x5c !== 'undefined') {
    try {
      x509CertificateChain = x509Parameters.x5c.map((pemCertificate) => {
        return new X509Certificate(Buffer.from(pemCertificate, 'base64'));
      });
    } catch (exception: unknown) {
      throw new InvalidJsonWebKeyException('The parameter "x5c" contains an invalid certificate.', {
        cause: exception,
      });
    }
  }

  x509CertificateChain.forEach((x509Certificate) => {
    const now = new Date();

    if (x509Certificate.validFromDate > now) {
      throw new InvalidJsonWebKeyException('The provided certificate is not yet valid.');
    }

    if (x509Certificate.validToDate < now) {
      throw new InvalidJsonWebKeyException('The provided certificate is expired.');
    }
  });

  // #region First certificate checks
  // TODO: Add keyUsage check when available.
  const firstCertificate = x509CertificateChain[0]!;

  if (Object.entries(firstCertificate.publicKey.export({ format: 'jwk' })).some(([k, v]) => jwkParameters[k] !== v)) {
    throw new InvalidJsonWebKeyException('The provided certificate did not sign the json web key.');
  }

  if (
    typeof x509Parameters.x5t !== 'undefined' &&
    Buffer.from(firstCertificate.fingerprint.replaceAll(':', ''), 'hex').toString('base64url') !== x509Parameters.x5t
  ) {
    throw new InvalidJsonWebKeyException('The certificate\'s SHA-1 Fingerprint does not match the value at "x5t".');
  }

  if (
    typeof x509Parameters['x5t#S256'] !== 'undefined' &&
    Buffer.from(firstCertificate.fingerprint256.replaceAll(':', ''), 'hex').toString('base64url') !==
      x509Parameters['x5t#S256']
  ) {
    throw new InvalidJsonWebKeyException(
      'The certificate\'s SHA-256 Fingerprint does not match the value at "x5t#S256".',
    );
  }
  // #endregion

  // #region Remaining certificates checks
  for (let i = 0; i < x509CertificateChain.length - 1; i++) {
    if (!x509CertificateChain[i]!.verify(x509CertificateChain[i + 1]!.publicKey)) {
      throw new InvalidJsonWebKeyException('A certificate in the chain was not successfully verified.');
    }
  }
  // #endregion
}

/**
 * Accesses the provided URL and parses the X.509 Certificate Chain.
 *
 * @param x5u X.509 Certificate Chain URL provided in the JSON Web Key Parameters.
 * @returns X.509 Certificate Chain from the URL.
 */
function getX5UCertificateChain(x5u: string): X509Certificate[] {
  let x509CertificateChain!: X509Certificate[];

  https.get(x5u, (res) => {
    let responseBody = '';

    res.on('data', (chunk) => (responseBody += chunk));
    res.on('end', () => {
      try {
        x509CertificateChain =
          responseBody
            .replaceAll('\n', '')
            .match(/-----BEGIN CERTIFICATE-----.*-----END CERTIFICATE-----/)!
            .map((x509Certificate) => x509Certificate.replaceAll(/-----\w+ CERTIFICATE-----/g, ''))
            .map((pemCertificate) => new X509Certificate(Buffer.from(pemCertificate, 'base64'))) ?? null;
      } catch (exception: unknown) {
        throw new InvalidJsonWebKeyException('The parameter "x5u" contains an invalid certificate.', {
          cause: exception,
        });
      }
    });
  });

  return x509CertificateChain;
}
