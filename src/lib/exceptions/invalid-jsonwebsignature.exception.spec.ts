import { InvalidJsonWebSignatureException } from './invalid-jsonwebsignature.exception';

describe('Invalid JSON Web Signature Exception', () => {
  it('should have a default error message.', () => {
    const exception = new InvalidJsonWebSignatureException();
    expect(exception.error).toEqual('The provided JSON Web Signature is invalid.');
  });
});
