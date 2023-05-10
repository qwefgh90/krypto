package krypto.exception;

public class WrongInitialVectorException extends Exception {
    public WrongInitialVectorException() {
    }

    public WrongInitialVectorException(String message) {
        super(message);
    }

    public WrongInitialVectorException(String message, Throwable cause) {
        super(message, cause);
    }

    public WrongInitialVectorException(Throwable cause) {
        super(cause);
    }

    public WrongInitialVectorException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
