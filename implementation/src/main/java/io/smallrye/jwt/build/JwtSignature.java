package io.smallrye.jwt.build;

import java.security.PrivateKey;

import javax.crypto.SecretKey;

/**
 * JWT JsonWebSignature
 */
public interface JwtSignature {

    /**
     * Sign the claims with {@link PrivateKey}
     * 
     * @param signingKey the signing key
     * @return signed JWT token
     * @throws JwtSignatureException the exception if the signing operation has failed
     */
    String sign(PrivateKey signingKey) throws JwtSignatureException;

    /**
     * Sign the claims with {@link SecretKey}
     * 
     * @param signingKey the signing key
     * @return signed JWT token
     * @throws JwtSignatureException the exception if the signing operation has failed
     */
    String sign(SecretKey signingKey) throws JwtSignatureException;

    /**
     * Sign the claims with a key loaded from the location set with the "smallrye.jwt.sign.key-location" property.
     * 
     * @return signed JWT token
     * @throws JwtSignatureException the exception if the signing operation has failed
     */
    String sign() throws JwtSignatureException;

    /**
     * Sign the claims with {@link PrivateKey} and encrypt the inner JWT by moving to {@link JwtEncryption}.
     *
     * @param signingKey the signing key
     * @return JwtEncryption
     * @throws JwtSignatureException the exception if the inner JWT signing operation has failed
     */
    JwtEncryption innerSign(PrivateKey signingKey) throws JwtSignatureException;

    /**
     * Sign the claims with {@link SecretKey} and encrypt the inner JWT by moving to {@link JwtEncryptionBuilder}.
     * 
     * @param signingKey the signing key
     * @return JwtEncryption
     * @throws JwtSignatureException the exception if the inner JWT signing operation has failed
     */
    JwtEncryption innerSign(SecretKey signingKey) throws JwtSignatureException;

    /**
     * Sign the claims with a key loaded from the location set with the "smallrye.jwt.sign.key-location" property
     * and encrypt the inner JWT by moving to {@link JwtEncryptionBuilder}.
     * 
     * If no "smallrye.jwt.sign.key-location" property is set then an insecure inner JWT with a "none" algorithm
     * has to be created before being encrypted.
     * 
     * @return JwtEncryption
     * @throws JwtSignatureException the exception if the inner JWT signing operation has failed
     */
    JwtEncryption innerSign() throws JwtSignatureException;

}
