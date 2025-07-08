import { InvalidJsonWebKeyException } from './invalid-jsonwebkey.exception';

describe('Invalid JSON Web Key Exception', () => {
  it('should have a default error message.', () => {
    const exception = new InvalidJsonWebKeyException();
    expect(exception.error).toEqual('The provided JSON Web Key is invalid.');
  });
});
