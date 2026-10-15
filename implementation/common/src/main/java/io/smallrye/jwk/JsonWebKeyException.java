package io.smallrye.jwk;

/**
 * The exception indicating that a JSON Web Key is invalid or can not be converted to or from a key.
 */
public class JsonWebKeyException extends Exception {

    private static final long serialVersionUID = 1L;

    public JsonWebKeyException(String message) {
        super(message);
    }

    public JsonWebKeyException(String message, Throwable cause) {
        super(message, cause);
    }
}
