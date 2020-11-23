package io.smallrye.jwt.build;

import java.security.PrivateKey;

import javax.crypto.SecretKey;

/**
 * JWT JsonWebSignature.
 */
public interface JwtSignature {

    /**
     * Sign the claims with {@link PrivateKey}.
     * 'RS256' algorithm will be used unless a different one has been set with {@code JwtSignatureBuilder}.
     * A key of size 2048 bits or larger MUST be used with the 'RS256' algorithm.
     * 
     * @param signingKey the signing key
     * @return signed JWT token
     * @throws JwtSignatureException the exception if the signing operation has failed
     */
    String sign(PrivateKey signingKey) throws JwtSignatureException;

    /**
     * Sign the claims with {@link SecretKey}
     * 'RS256' algorithm will be used unless a different one has been set with {@code JwtSignatureBuilder}.
     * A key of size 2048 bits or larger MUST be used with the 'RS256' algorithm.
     *
     * @param signingKey the signing key
     * @return signed JWT token
     * @throws JwtSignatureException the exception if the signing operation has failed
     */
    String sign(SecretKey signingKey) throws JwtSignatureException;

    /**
     * Sign the claims with a private or secret key loaded from the custom location
     * which can point to a PEM, JWK or JWK set keys.
     * 'RS256' algorithm will be used unless a different one has been set with {@code JwtSignatureBuilder}.
     * A key of size 2048 bits or larger MUST be used with the 'RS256' algorithm.
     * 
     * @param keyLocation the signing key location
     * @return signed JWT token
     * @throws JwtSignatureException the exception if the signing operation has failed
     */
    String sign(String keyLocation) throws JwtSignatureException;

    /**
     * Sign the claims with a key loaded from the location set with the "smallrye.jwt.sign.key-location" property
     * which can point to a PEM, JWK or JWK set keys.
     * 'RS256' algorithm will be used unless a different one has been set with {@code JwtSignatureBuilder}.
     * A key of size 2048 bits or larger MUST be used with the 'RS256' algorithm.
     *
     * @return signed JWT token
     * @throws JwtSignatureException the exception if the signing operation has failed
     */
    String sign() throws JwtSignatureException;

    /**
     * Sign the claims with a secret key string.
     * 'HS256' algorithm will be used unless a different one has been set with {@code JwtSignatureBuilder}.
     *
     * @param secret the secret
     * @return signed JWT token
     * @throws JwtSignatureException the exception if the signing operation has failed
     */
    String signWithSecret(String secret) throws JwtSignatureException;

    /**
     * Sign the claims with {@link PrivateKey} and encrypt the inner JWT by moving to {@link JwtEncryptionBuilder}.
     * 'RS256' algorithm will be used unless a different one has been set with {@code JwtSignatureBuilder}.
     * A key of size 2048 bits or larger MUST be used with the 'RS256' algorithm.
     *
     * @param signingKey the signing key
     * @return JwtEncryption
     * @throws JwtSignatureException the exception if the inner JWT signing operation has failed
     */
    JwtEncryptionBuilder innerSign(PrivateKey signingKey) throws JwtSignatureException;

    /**
     * Sign the claims with {@link SecretKey} and encrypt the inner JWT by moving to {@link JwtEncryptionBuilder}.
     * 'RS256' algorithm will be used unless a different one has been set with {@code JwtSignatureBuilder}.
     * A key of size 2048 bits or larger MUST be used with the 'RS256' algorithm.
     *
     * @param signingKey the signing key
     * @return JwtEncryption
     * @throws JwtSignatureException the exception if the inner JWT signing operation has failed
     */
    JwtEncryptionBuilder innerSign(SecretKey signingKey) throws JwtSignatureException;

    /**
     * Sign the claims with a private or secret key loaded from the custom location
     * which can point to a PEM, JWK or JWK set keys and encrypt the inner JWT by moving to {@link JwtEncryptionBuilder}.
     * 'RS256' algorithm will be used unless a different one has been set with {@code JwtSignatureBuilder}.
     * A key of size 2048 bits or larger MUST be used with the 'RS256' algorithm.
     *
     * @param keyLocation the signing key location
     * @return JwtEncryption
     * @throws JwtSignatureException the exception if the inner JWT signing operation has failed
     */
    JwtEncryptionBuilder innerSign(String keyLocation) throws JwtSignatureException;

    /**
     * Sign the claims with a key loaded from the location set with the "smallrye.jwt.sign.key-location" property
     * and encrypt the inner JWT by moving to {@link JwtEncryptionBuilder}.
     *
     * If no "smallrye.jwt.sign.key-location" property and 'alg' algorithm header have been set then an insecure
     * inner JWT with a "none" algorithm has to be created before being encrypted.
     * A key of size 2048 bits or larger MUST be used with the 'RS256' algorithm.
     * 
     * @return JwtEncryption
     * @throws JwtSignatureException the exception if the inner JWT signing operation has failed
     */
    JwtEncryptionBuilder innerSign() throws JwtSignatureException;

    /**
     * Sign the claims with a secret key string and encrypt the inner JWT by moving to {@link JwtEncryptionBuilder}.
     * 'HS256' algorithm will be used unless a different one has been set with {@code JwtSignatureBuilder}.
     *
     * @param secret the secret
     * @return signed JWT token
     * @throws JwtSignatureException the exception if the signing operation has failed
     */
    JwtEncryptionBuilder innerSignWithSecret(String secret) throws JwtSignatureException;
}
