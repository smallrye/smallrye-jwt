package io.smallrye.jwt.auth;

/**
 * A signed token, as given to a {@link VerificationKeyResolver} to select a verification key.
 * <p>
 * The token signature has not been verified yet, so neither the headers nor the payload can be trusted.
 */
public interface JsonWebSignature {

    /**
     * The token JOSE headers.
     */
    JwsHeaders headers();

    /**
     * The token payload, decoded but not verified.
     */
    String unverifiedPayload();

    /**
     * The token in its compact serialization form.
     */
    String serialized();
}
