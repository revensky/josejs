import { JwsAlg } from '../../../jws/jws.alg';
import { HS384JwsBackend } from './hs384-jws.backend';

describe('HS384 JSON Web Signature Backend', () => {
  const backend = new HS384JwsBackend();

  describe('algorithm', () => {
    it('should have "HS384" as its value.', () => {
      expect(backend['algorithm']).toEqual<JwsAlg>('HS384');
    });
  });

  describe('hash', () => {
    it('should have "sha384" as its value.', () => {
      expect(backend['hash']).toEqual<'sha256' | 'sha384' | 'sha512'>('sha384');
    });
  });

  describe('keySize', () => {
    it('should have 48 as its value.', () => {
      expect(backend['keySize']).toEqual(48);
    });
  });
});
