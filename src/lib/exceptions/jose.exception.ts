/**
 * Base JOSE Exception.
 */
export abstract class JoseException extends Error {
  /**
   * Default JOSE Exception Error Message.
   */
  public abstract readonly error: string;

  /**
   * Instantiates a new JOSE Exception with a default error message.
   */
  public constructor();

  /**
   * Instantiates a new JOSE Exception with the provided error message.
   *
   * @param message Error Message.
   */
  public constructor(message: string);

  /**
   * Instantiates a new JOSE Exception with a default error message and the provided error options.
   *
   * @param options Error Options.
   */
  public constructor(options: ErrorOptions);

  /**
   * Instantiates a new JOSE Exception with the provided error message and error options.
   *
   * @param message Error Message.
   * @param options Error Options.
   */
  public constructor(message: string, options: ErrorOptions);

  /**
   * Instantiates a new JOSE Exception with the provided parameters.
   *
   * @param messageOrOptions Error Message or Error Options.
   * @param options Error Options.
   */
  public constructor(messageOrOptions?: string | ErrorOptions, options?: ErrorOptions) {
    switch (true) {
      case typeof messageOrOptions !== 'undefined' && typeof messageOrOptions !== 'string':
        super(undefined, messageOrOptions);
        break;

      case typeof messageOrOptions === 'string':
        super(messageOrOptions, options);
        break;

      default:
        super();
        break;
    }
  }

  /**
   * Error Message.
   */
  public override get message(): string {
    return super.message !== '' ? super.message : this.error;
  }
}
