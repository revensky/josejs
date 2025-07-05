import { JoseException } from './jose.exception';

class CustomJoseException extends JoseException {
  public readonly error: string = 'Custom JOSE Exception.';
}

describe('JOSE Exception', () => {
  describe('constructor', () => {
    it('should return a jose exception with the default error message and no error options.', () => {
      const exception = new CustomJoseException();

      expect(exception).toBeInstanceOf(JoseException);
      expect(exception.message).toEqual('Custom JOSE Exception.');
      expect(exception.cause).toBeUndefined();
    });

    it('should return a jose exception with the provided error message and no error options.', () => {
      const exception = new CustomJoseException('Custom error message.');

      expect(exception).toBeInstanceOf(JoseException);
      expect(exception.message).toEqual('Custom error message.');
      expect(exception.cause).toBeUndefined();
    });

    it('should return a jose exception with the default error message and the provided error options.', () => {
      const exception = new CustomJoseException({ cause: new TypeError() });

      expect(exception).toBeInstanceOf(JoseException);
      expect(exception.message).toEqual('Custom JOSE Exception.');
      expect(exception.cause).toBeInstanceOf(TypeError);
    });

    it('should return a jose exception with the provided error message and the provided error options.', () => {
      const exception = new CustomJoseException('Custom error message.', { cause: new TypeError() });

      expect(exception).toBeInstanceOf(JoseException);
      expect(exception.message).toEqual('Custom error message.');
      expect(exception.cause).toBeInstanceOf(TypeError);
    });
  });
});
