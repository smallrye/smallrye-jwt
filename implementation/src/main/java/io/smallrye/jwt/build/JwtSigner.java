package io.smallrye.jwt.build;

import java.security.PrivateKey;

import javax.crypto.SecretKey;

/**
 * JWT Signer
 */
public interface JwtSigner {

    /**
     * Sign a token using {@link PrivateKey}
     * 
     * @param signingKey the signing key
     * @return signed JWT token
     * @throws JwtException the exception if the signing operation has failed
     */
    String sign(PrivateKey signingKey) throws JwtException;

    /**
     * Sign a token using {@link SecretKey}
     * 
     * @param signingKey the signing key
     * @return signed JWT token
     * @throws JwtException the exception if the signing operation has failed
     */
    String sign(SecretKey signingKey) throws JwtException;

    /**
     * Sign a token using a key loaded from the location set with the "smallrye.jwt.sign.private-key-location" property.
     * 
     * @return signed JWT token
     * @throws JwtException the exception if the signing operation has failed
     */
    String sign() throws JwtException;

}
