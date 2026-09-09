package io.smallrye.jwt.auth;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * The JOSE headers of a signed token.
 */
public interface JwsHeaders {

    /**
     * The {@code kid} header, may be null.
     */
    String keyId();

    /**
     * The {@code alg} header.
     */
    String algorithm();

    /**
     * The {@code typ} header, may be null.
     */
    String type();

    /**
     * The {@code cty} header, may be null.
     */
    String contentType();

    /**
     * The {@code x5t} header, a base64url encoded SHA-1 certificate thumbprint, may be null.
     */
    String x509CertificateThumbprint();

    /**
     * The {@code x5t#S256} header, a base64url encoded SHA-256 certificate thumbprint, may be null.
     */
    String x509CertificateSha256Thumbprint();

    /**
     * The certificates of the {@code x5c} header, in the order they appear in the token,
     * or null if the token has no {@code x5c} header.
     *
     * @throws UnresolvableKeyException if the {@code x5c} header is present but can not be parsed
     */
    List<X509Certificate> x509CertificateChain() throws UnresolvableKeyException;

    /**
     * The value of an arbitrary header, may be null.
     */
    Object header(String name);
}
