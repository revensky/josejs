import { Buffer } from 'buffer';

import { JwsAlg } from '../../../jws/jws.alg';
import { NoneJwsBackend } from './none-jws.backend';

describe('none JSON Web Signature Backend', () => {
  const backend = new NoneJwsBackend();
  const message = Buffer.from('Super secret message.');

  describe('algorithm', () => {
    it('should have "EdDSA" as its value.', () => {
      expect(backend['algorithm']).toEqual<JwsAlg>('none');
    });
  });

  describe('keyType', () => {
    it('should be null.', () => {
      expect(backend['keyType']).toBeNull();
    });
  });

  describe('sign()', () => {
    it('should return a zero-byte buffer object.', async () => {
      const signature = await backend.sign(message, null);

      expect(signature).toStrictEqual(Buffer.alloc(0));
    });
  });

  describe('verify()', () => {
    it('should return true.', async () => {
      const signature: string = 'babecafe';

      await expect(backend.verify(Buffer.from(signature, 'base64url'), message, null)).resolves.toBeTrue();
    });
  });
});
