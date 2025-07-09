import { InvalidJsonWebKeySetException } from './invalid-jsonwebkeyset.exception';

describe('Invalid JSON Web Key Set Exception', () => {
  it('should have a default error message.', () => {
    const exception = new InvalidJsonWebKeySetException();
    expect(exception.error).toEqual('The provided JSON Web Key Set is invalid.');
  });
});
