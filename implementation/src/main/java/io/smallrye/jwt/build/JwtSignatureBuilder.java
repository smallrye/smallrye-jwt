package io.smallrye.jwt.build;

import java.security.PrivateKey;

import javax.crypto.SecretKey;

import io.smallrye.jwt.algorithm.SignatureAlgorithm;

/**
 * JWT JsonWebSignature Builder.
 * 
 * <p>
 * JwtSignatureBuilder implementations must set the 'alg' (algorithm) header to 'RS256'
 * and 'typ' (token type) header to 'JWT' unless they have already been set.
 * <p>
 * Note that JwtSignatureBuilder implementations are not expected to be thread-safe.
 * 
 * @see <a href="https://tools.ietf.org/html/rfc7515">RFC7515</a>
 */
public interface JwtSignatureBuilder extends JwtSignature {

    /**
     * Set a signature algorithm
     * 
     * @param algorithm the signature algorithm
     * @return JwtSignatureBuilder
     */
    JwtSignatureBuilder signatureAlgorithm(SignatureAlgorithm algorithm);

    /**
     * Set a 'kid' signature key id
     * 
     * @param keyId the key id
     * @return JwtSignatureBuilder
     */
    JwtSignatureBuilder signatureKeyId(String keyId);

    /**
     * Custom JWT signature header
     * 
     * If the 'alg' (algorithm) header is set with this method then it
     * has to match one of the {@link SignatureAlgorithm} values.
     * 
     * @param name the header name
     * @param value the header value
     * @return JwtSignatureBuilder
     */
    JwtSignatureBuilder header(String name, Object value);

    /**
     * Sign the claims with {@link PrivateKey} and encrypt the inner JWT by moving to {@link JwtEncryptionBuilder}.
     *
     * @param signingKey the signing key
     * @return JwtEncryptionBuilder
     * @throws JwtSignatureException the exception if the inner JWT signing operation has failed
     */
    JwtEncryptionBuilder innerSign(PrivateKey signingKey) throws JwtSignatureException;

    /**
     * Sign the claims with {@link SecretKey} and encrypt the inner JWT by moving to {@link JwtEncryptionBuilder}.
     * 
     * @param signingKey the signing key
     * @return JwtEncryptionBuilder
     * @throws JwtSignatureException the exception if the inner JWT signing operation has failed
     */
    JwtEncryptionBuilder innerSign(SecretKey signingKey) throws JwtSignatureException;

    /**
     * Sign the claims with a key loaded from the location set with the "smallrye.jwt.sign.key-location" property
     * and encrypt the inner JWT by moving to {@link JwtEncryptionBuilder}.
     * 
     * If no "smallrye.jwt.sign.key-location" property is set then an insecure inner JWT with a "none" algorithm
     * has to be created before being encrypted.
     * 
     * @return JwtEncryptionBuilder
     * @throws JwtSignatureException the exception if the inner JWT signing operation has failed
     */
    JwtEncryptionBuilder innerSign() throws JwtSignatureException;

}
