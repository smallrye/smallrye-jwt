package io.smallrye.jwt.auth;

/**
 * The exception indicating that a JWT has expired.
 */
public class TokenExpiredException extends InvalidJWTException {

    private static final long serialVersionUID = 1L;

    public TokenExpiredException(String message) {
        super(message);
    }
}
