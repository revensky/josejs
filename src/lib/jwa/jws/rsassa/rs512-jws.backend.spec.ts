import { constants } from 'crypto';

import { JwsAlg } from '../../../jws/jws.alg';
import { RS512JwsBackend } from './rs512-jws.backend';

describe('RS512 JSON Web Signature Backend', () => {
  const backend = new RS512JwsBackend();

  describe('algorithm', () => {
    it('should have "RS512" as its value.', () => {
      expect(backend['algorithm']).toEqual<JwsAlg>('RS512');
    });
  });

  describe('hash', () => {
    it('should have "sha512" as its value.', () => {
      expect(backend['hash']).toEqual<'sha256' | 'sha384' | 'sha512'>('sha512');
    });
  });

  describe('padding', () => {
    it('should have the value of the constant "crypto.RSA_PKCS1_PADDING" as its value.', () => {
      expect(backend['padding']).toEqual(constants.RSA_PKCS1_PADDING);
    });
  });
});
