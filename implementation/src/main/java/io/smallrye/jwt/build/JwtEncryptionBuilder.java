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
     * Set an 'alg' key encryption algorithm
     * 
     * @param algorithm the key encryption algorithm
     * @return JwtEncryptionBuilder
     */
    JwtEncryptionBuilder keyEncryptionAlgorithm(KeyEncryptionAlgorithm algorithm);

    /**
     * Set an 'enc' content encryption algorithm
     * 
     * @param algorithm the content encryption algorithm
     * @return JwtEncryptionBuilder
     */
    JwtEncryptionBuilder contentEncryptionAlgorithm(ContentEncryptionAlgorithm algorithm);

    /**
     * Set a 'kid' key encryption key id
     * 
     * @param keyId the key id
     * @return JwtEncryptionBuilder
     */
    JwtEncryptionBuilder keyEncryptionKeyId(String keyId);

    /**
     * Custom JWT encryption header
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
