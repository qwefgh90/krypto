package krypto.exception;

public class WrongFixedKeySize extends Exception{
    public WrongFixedKeySize() {
    }

    public WrongFixedKeySize(String message) {
        super(message);
    }

    public WrongFixedKeySize(String message, Throwable cause) {
        super(message, cause);
    }

    public WrongFixedKeySize(Throwable cause) {
        super(cause);
    }

    public WrongFixedKeySize(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
