import { JwsAlg } from '../../../jws/jws.alg';
import { HS256JwsBackend } from './hs256-jws.backend';

describe('HS256 JSON Web Signature Backend', () => {
  const backend = new HS256JwsBackend();

  describe('algorithm', () => {
    it('should have "HS256" as its value.', () => {
      expect(backend['algorithm']).toEqual<JwsAlg>('HS256');
    });
  });

  describe('hash', () => {
    it('should have "sha256" as its value.', () => {
      expect(backend['hash']).toEqual<'sha256' | 'sha384' | 'sha512'>('sha256');
    });
  });

  describe('keySize', () => {
    it('should have 32 as its value.', () => {
      expect(backend['keySize']).toEqual(32);
    });
  });
});
