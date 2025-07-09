import { JsonWebKeyNotFoundException } from './jsonwebkey-not-found.exception';

describe('JSON Web Key Not Found Exception', () => {
  it('should have a default error message.', () => {
    const exception = new JsonWebKeyNotFoundException();
    expect(exception.error).toEqual('No JSON Web Key matches the criteria at the JSON Web Key Set.');
  });
});
