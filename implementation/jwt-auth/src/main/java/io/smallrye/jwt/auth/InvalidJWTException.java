package io.smallrye.jwt.auth;

/**
 * The general exception indicating that a JWT is invalid.
 */
public class InvalidJWTException extends Exception {

    private static final long serialVersionUID = 1L;

    public InvalidJWTException(String message) {
        super(message);
    }

    public InvalidJWTException(String message, Throwable cause) {
        super(message, cause);
    }
}
