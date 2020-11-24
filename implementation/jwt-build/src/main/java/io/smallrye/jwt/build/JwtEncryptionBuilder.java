package io.smallrye.jwt.build;

import io.smallrye.jwt.algorithm.ContentEncryptionAlgorithm;
import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;

/**
 * JWT JsonWebEncryption Builder.
 * 
 * <p>
 * JwtEncryptionBuilder implementations must set the 'alg' (algorithm) header to 'RSA-OAEP-256'
 * and 'enc' (content encryption algorithm) header to 'A256GCM' unless they have already been set.
 * The 'cty' (content type) header must be set to 'JWT' when the inner signed JWT is encrypted.
 * <p>
 * Note that JwtEncryptionBuilder implementations are not expected to be thread-safe.
 * 
 * @see <a href="https://tools.ietf.org/html/rfc7516">RFC7516</a>
 */
public interface JwtEncryptionBuilder extends JwtEncryption {

    /**
     * Set an 'alg' key encryption algorithm.
     * Note that only 'RSA-OAEP-256' (default), 'ECDH-ES+A256KW' and 'A256KW' algorithms must be supported.
     * A key of size 2048 bits or larger MUST be used with 'RSA-OAEP-256' algorithm.
     * 
     * @since 2.1.3
     *
     * @param algorithm the key encryption algorithm
     * @return JwtEncryptionBuilder
     */
    JwtEncryptionBuilder keyAlgorithm(KeyEncryptionAlgorithm algorithm);

    /**
     * Set an 'alg' key encryption algorithm.
     * Note that only 'RSA-OAEP-256' (default), 'ECDH-ES+A256KW' and 'A256KW' algorithms must be supported.
     * A key of size 2048 bits or larger MUST be used with 'RSA-OAEP-256' algorithm.
     *
     * @deprecated Use {@link #keyAlgorithm}
     *
     * @param algorithm the key encryption algorithm
     * @return JwtEncryptionBuilder
     */
    @Deprecated
    default JwtEncryptionBuilder keyEncryptionAlgorithm(KeyEncryptionAlgorithm algorithm) {
        return keyAlgorithm(algorithm);
    }

    /**
     * Set an 'enc' content encryption algorithm.
     * Note that only 'A256GCM' (default) and 'A128CBC-HS256' algorithms must be supported.
     *
     * @since 2.1.3
     *
     * @param algorithm the content encryption algorithm
     * @return JwtEncryptionBuilder
     */
    JwtEncryptionBuilder contentAlgorithm(ContentEncryptionAlgorithm algorithm);

    /**
     * Set an 'enc' content encryption algorithm.
     * Note that only 'A256GCM' (default) and 'A128CBC-HS256' algorithms must be supported.
     *
     * @deprecated Use {@link #contentAlgorithm}
     * 
     * @param algorithm the content encryption algorithm
     * @return JwtEncryptionBuilder
     */
    @Deprecated
    default JwtEncryptionBuilder contentEncryptionAlgorithm(ContentEncryptionAlgorithm algorithm) {
        return contentAlgorithm(algorithm);
    }

    /**
     * Set a 'kid' key encryption key id.
     *
     * @since 2.1.3
     *
     * @param keyId the key id
     * @return JwtEncryptionBuilder
     */
    JwtEncryptionBuilder keyId(String keyId);

    /**
     * Set a 'kid' key encryption key id.
     *
     * @deprecated Use {@link #keyId}
     * 
     * @param keyId the key id
     * @return JwtEncryptionBuilder
     */
    @Deprecated
    default JwtEncryptionBuilder keyEncryptionKeyId(String keyId) {
        return keyId(keyId);
    }

    /**
     * Custom JWT encryption header.
     * 
     * If the 'alg' (algorithm) header is set with this method then it
     * has to match one of the {@link KeyEncryptionAlgorithm} values.
     * 
     * If the 'enc' (encryption) header is set with this method then it
     * has to match one of the {@link ContentEncryptionAlgorithm} values.
     * 
     * @param name the header name
     * @param value the header value
     * @return JwtEncryptionBuilder
     */
    JwtEncryptionBuilder header(String name, Object value);
}
