import { JwsAlg } from '../../../jws/jws.alg';
import { HS512JwsBackend } from './hs512-jws.backend';

describe('HS512 JSON Web Signature Backend', () => {
  const backend = new HS512JwsBackend();

  describe('algorithm', () => {
    it('should have "HS512" as its value.', () => {
      expect(backend['algorithm']).toEqual<JwsAlg>('HS512');
    });
  });

  describe('hash', () => {
    it('should have "sha512" as its value.', () => {
      expect(backend['hash']).toEqual<'sha256' | 'sha384' | 'sha512'>('sha512');
    });
  });

  describe('keySize', () => {
    it('should have 64 as its value.', () => {
      expect(backend['keySize']).toEqual(64);
    });
  });
});
