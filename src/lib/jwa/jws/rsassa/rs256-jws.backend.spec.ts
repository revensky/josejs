import { constants } from 'crypto';

import { JwsAlg } from '../../../jws/jws.alg';
import { RS256JwsBackend } from './rs256-jws.backend';

describe('RS256 JSON Web Signature Backend', () => {
  const backend = new RS256JwsBackend();

  describe('algorithm', () => {
    it('should have "RS256" as its value.', () => {
      expect(backend['algorithm']).toEqual<JwsAlg>('RS256');
    });
  });

  describe('hash', () => {
    it('should have "sha256" as its value.', () => {
      expect(backend['hash']).toEqual<'sha256' | 'sha384' | 'sha512'>('sha256');
    });
  });

  describe('padding', () => {
    it('should have the value of the constant "crypto.RSA_PKCS1_PADDING" as its value.', () => {
      expect(backend['padding']).toEqual(constants.RSA_PKCS1_PADDING);
    });
  });
});
