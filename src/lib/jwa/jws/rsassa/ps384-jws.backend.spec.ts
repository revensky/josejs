import { constants } from 'crypto';

import { JwsAlg } from '../../../jws/jws.alg';
import { PS384JwsBackend } from './ps384-jws.backend';

describe('PS384 JSON Web Signature Backend', () => {
  const backend = new PS384JwsBackend();

  describe('algorithm', () => {
    it('should have "PS384" as its value.', () => {
      expect(backend['algorithm']).toEqual<JwsAlg>('PS384');
    });
  });

  describe('hash', () => {
    it('should have "sha384" as its value.', () => {
      expect(backend['hash']).toEqual<'sha256' | 'sha384' | 'sha512'>('sha384');
    });
  });

  describe('padding', () => {
    it('should have the value of the constant "crypto.RSA_PKCS1_PSS_PADDING" as its value.', () => {
      expect(backend['padding']).toEqual(constants.RSA_PKCS1_PSS_PADDING);
    });
  });
});
