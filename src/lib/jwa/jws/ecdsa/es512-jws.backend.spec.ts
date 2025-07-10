import { JwsAlg } from '../../../jws/jws.alg';
import { JwkCrv } from '../../jwk/jwk.crv';
import { ES512JwsBackend } from './es512-jws.backend';

describe('ES512 JSON Web Signature Backend', () => {
  const backend = new ES512JwsBackend();

  describe('algorithm', () => {
    it('should have "ES512" as its value.', () => {
      expect(backend['algorithm']).toEqual<JwsAlg>('ES512');
    });
  });

  describe('hash', () => {
    it('should have "sha512" as its value.', () => {
      expect(backend['hash']).toEqual<'sha256' | 'sha384' | 'sha512'>('sha512');
    });
  });

  describe('curve', () => {
    it('should have "P-521" as its value.', () => {
      expect(backend['curve']).toEqual<JwkCrv>('P-521');
    });
  });
});
