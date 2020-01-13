package io.smallrye.jwt.build;

/**
 * Base JWT Exception
 */
@SuppressWarnings("serial")
public class JwtException extends RuntimeException {
    public JwtException() {
    }

    public JwtException(String errorMessage) {
        super(errorMessage);
    }

    public JwtException(Throwable t) {
        super(t);
    }

    public JwtException(String errorMessage, Throwable t) {
        super(errorMessage, t);
    }
}
