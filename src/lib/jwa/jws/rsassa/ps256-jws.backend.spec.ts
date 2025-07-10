import { constants } from 'crypto';

import { JwsAlg } from '../../../jws/jws.alg';
import { PS256JwsBackend } from './ps256-jws.backend';

describe('PS256 JSON Web Signature Backend', () => {
  const backend = new PS256JwsBackend();

  describe('algorithm', () => {
    it('should have "PS256" as its value.', () => {
      expect(backend['algorithm']).toEqual<JwsAlg>('PS256');
    });
  });

  describe('hash', () => {
    it('should have "sha256" as its value.', () => {
      expect(backend['hash']).toEqual<'sha256' | 'sha384' | 'sha512'>('sha256');
    });
  });

  describe('padding', () => {
    it('should have the value of the constant "crypto.RSA_PKCS1_PSS_PADDING" as its value.', () => {
      expect(backend['padding']).toEqual(constants.RSA_PKCS1_PSS_PADDING);
    });
  });
});
