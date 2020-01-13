package io.smallrye.jwt.build;

import java.security.PublicKey;

import javax.crypto.SecretKey;

/**
 * JWT JsonWebEncryption
 */
public interface JwtEncryption {

    /**
     * Encrypt the claims or inner JWT with {@link PublicKey}
     * 
     * @param keyEncryptionKey the key which encrypts the content encryption key
     * @return encrypted JWT token
     * @throws JwtEncryptionException the exception if the encryption operation has failed
     */
    String encrypt(PublicKey keyEncryptionKey) throws JwtEncryptionException;

    /**
     * Encrypt the claims or inner JWT with {@link SecretKey}
     * 
     * @param keyEncryptionKey the key which encrypts the content encryption key
     * @return encrypted JWT token
     * @throws JwtEncryptionException the exception if the encryption operation has failed
     */
    String encrypt(SecretKey keyEncryptionKey) throws JwtEncryptionException;

    /**
     * Encrypt the claims or inner JWT with a key loaded from the location set with the
     * "smallrye.jwt.encrypt.key-location" property.
     * 
     * @return signed JWT token
     * @throws JwtSignatureException the exception if the signing operation has failed
     */
    String encrypt() throws JwtSignatureException;

}
