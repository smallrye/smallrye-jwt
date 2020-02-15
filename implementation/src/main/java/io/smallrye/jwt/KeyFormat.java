package io.smallrye.jwt;

/**
 * Format or store type of the security key.
 */
public enum KeyFormat {
    /**
     * PEM file containing a Base64-encoded key.
     */
    PEM_KEY,
    /**
     * PEM file containing a Base64-encoded certificate.
     */
    PEM_CERTIFICATE,

    /**
     * JWK key set or single JWK key.
     */
    JWK,

    /**
     * JWK key set or single JWK key which has been Base64URL-encoded.
     */
    JWK_BASE64URL,

    /**
     * Key can be in any of the supported formats.
     */
    ANY
}
