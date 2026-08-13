package io.smallrye.jwt.auth;

import io.smallrye.jwt.auth.principal.JsonWebSignatureImpl;

/**
 * A signed token, as given to a {@link VerificationKeyResolver} to select a verification key.
 * <p>
 * The token signature has not been verified yet, so neither the headers nor the payload can be trusted.
 */
public interface JsonWebSignature {

    /**
     * Parse a signed token in its compact serialization form.
     * <p>
     * Only the token format is checked, its signature is not verified.
     *
     * @param token the token in its compact serialization form
     * @return the signed token
     * @throws InvalidJWTException if the token is not a well formed signed token
     */
    static JsonWebSignature parse(String token) throws InvalidJWTException {
        return JsonWebSignatureImpl.parse(token);
    }

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
