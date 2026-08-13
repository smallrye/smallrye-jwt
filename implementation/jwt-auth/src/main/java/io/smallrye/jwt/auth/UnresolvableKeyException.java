package io.smallrye.jwt.auth;

public class UnresolvableKeyException extends Exception {

    private static final long serialVersionUID = 1L;

    public UnresolvableKeyException(String message) {
        super(message);
    }

    public UnresolvableKeyException(String message, Throwable cause) {
        super(message, cause);
    }
}
