package io.smallrye.jwt.auth;

import java.security.Key;

/**
 * Resolves decryption keys for JWT token decryption.
 * <p>
 * The resolver is given the token JOSE headers and its serialized form, see {@link JsonWebEncryption}.
 */
public interface DecryptionKeyResolver {
    Key resolveKey(JsonWebEncryption jwe) throws UnresolvableKeyException;
}
