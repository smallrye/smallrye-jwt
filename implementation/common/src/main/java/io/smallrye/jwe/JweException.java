package io.smallrye.jwe;

/**
 * The exception indicating that a JSON Web Encryption sequence can not be created or decrypted.
 */
public class JweException extends Exception {

    private static final long serialVersionUID = 1L;

    public JweException(String message) {
        super(message);
    }

    public JweException(String message, Throwable cause) {
        super(message, cause);
    }
}
