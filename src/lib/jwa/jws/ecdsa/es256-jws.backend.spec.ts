import { JwsAlg } from '../../../jws/jws.alg';
import { JwkCrv } from '../../jwk/jwk.crv';
import { ES256JwsBackend } from './es256-jws.backend';

describe('ES256 JSON Web Signature Backend', () => {
  const backend = new ES256JwsBackend();

  describe('algorithm', () => {
    it('should have "ES256" as its value.', () => {
      expect(backend['algorithm']).toEqual<JwsAlg>('ES256');
    });
  });

  describe('hash', () => {
    it('should have "sha256" as its value.', () => {
      expect(backend['hash']).toEqual<'sha256' | 'sha384' | 'sha512'>('sha256');
    });
  });

  describe('curve', () => {
    it('should have "P-256" as its value.', () => {
      expect(backend['curve']).toEqual<JwkCrv>('P-256');
    });
  });
});
