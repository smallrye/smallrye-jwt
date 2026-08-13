package io.smallrye.jwt.auth;

/**
 * The JOSE headers of an encrypted token.
 */
public interface JweHeaders {

    /**
     * The {@code kid} header, may be null.
     */
    String keyId();

    /**
     * The {@code alg} key management header.
     */
    String algorithm();

    /**
     * The {@code enc} content encryption header.
     */
    String encryptionAlgorithm();

    /**
     * The {@code typ} header, may be null.
     */
    String type();

    /**
     * The {@code cty} header, may be null.
     */
    String contentType();

    /**
     * The value of an arbitrary header, may be null.
     */
    Object header(String name);
}
