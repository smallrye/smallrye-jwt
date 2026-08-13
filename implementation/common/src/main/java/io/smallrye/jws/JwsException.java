package io.smallrye.jws;

/**
 * The exception indicating that a JSON Web Signature sequence can not be created or verified.
 */
public class JwsException extends Exception {

    private static final long serialVersionUID = 1L;

    public JwsException(String message) {
        super(message);
    }

    public JwsException(String message, Throwable cause) {
        super(message, cause);
    }
}
