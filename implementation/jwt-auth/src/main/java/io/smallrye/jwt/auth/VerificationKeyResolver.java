package io.smallrye.jwt.auth;

import java.security.Key;

import io.smallrye.jws.JsonWebSignature;

/**
 * Resolves verification keys for JWT signature verification.
 * <p>
 * The resolver is given the token JOSE headers, its unverified payload and its serialized form,
 * see {@link JsonWebSignature}.
 */
public interface VerificationKeyResolver {
    Key resolveKey(JsonWebSignature jws) throws UnresolvableKeyException;
}
