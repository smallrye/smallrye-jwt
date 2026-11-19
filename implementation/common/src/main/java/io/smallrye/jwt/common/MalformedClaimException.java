package io.smallrye.jwt.common;

/**
 * Thrown when a claim value does not have the expected type, for example, when a string claim is requested
 * but the claim value is a number.
 */
public class MalformedClaimException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public MalformedClaimException(String message) {
        super(message);
    }
}
