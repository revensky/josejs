import { JwsAlg } from '../../../jws/jws.alg';
import { JwkCrv } from '../../jwk/jwk.crv';
import { ES384JwsBackend } from './es384-jws.backend';

describe('ES384 JSON Web Signature Backend', () => {
  const backend = new ES384JwsBackend();

  describe('algorithm', () => {
    it('should have "ES384" as its value.', () => {
      expect(backend['algorithm']).toEqual<JwsAlg>('ES384');
    });
  });

  describe('hash', () => {
    it('should have "sha384" as its value.', () => {
      expect(backend['hash']).toEqual<'sha256' | 'sha384' | 'sha512'>('sha384');
    });
  });

  describe('curve', () => {
    it('should have "P-384" as its value.', () => {
      expect(backend['curve']).toEqual<JwkCrv>('P-384');
    });
  });
});
