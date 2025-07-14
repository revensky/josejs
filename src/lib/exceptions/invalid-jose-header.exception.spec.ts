import { InvalidJoseHeaderException } from './invalid-jose-header.exception';

describe('Invalid JOSE Header Exception', () => {
  it('should have a default error message.', () => {
    const exception = new InvalidJoseHeaderException();
    expect(exception.error).toEqual('The provided JOSE Header is invalid.');
  });
});
