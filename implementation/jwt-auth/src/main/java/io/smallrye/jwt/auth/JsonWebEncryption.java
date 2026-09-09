package io.smallrye.jwt.auth;

/**
 * An encrypted token, as given to a {@link DecryptionKeyResolver} to select a decryption key.
 * <p>
 * The token has not been decrypted yet, so only its headers are available.
 */
public interface JsonWebEncryption {

    /**
     * The token JOSE headers.
     */
    JweHeaders headers();

    /**
     * The token in its compact serialization form.
     */
    String serialized();
}
