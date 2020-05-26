package io.smallrye.jwt.build;

import java.security.PublicKey;

import javax.crypto.SecretKey;

/**
 * JWT JsonWebEncryption.
 */
public interface JwtEncryption {

    /**
     * Encrypt the claims or inner JWT with {@link PublicKey}.
     * 'RSA-OAEP-256' key and 'A256GCM' content encryption algorithms will be used
     * unless different ones have been set with {@code JwtEncryptionBuilder}.
     * A key of size 2048 bits or larger MUST be used with the 'RSA-OAEP' and 'RSA-OAEP-256' algorithms.
     *
     * @param keyEncryptionKey the key which encrypts the content encryption key
     * @return encrypted JWT token
     * @throws JwtEncryptionException the exception if the encryption operation has failed
     */
    String encrypt(PublicKey keyEncryptionKey) throws JwtEncryptionException;

    /**
     * Encrypt the claims or inner JWT with {@link SecretKey}.
     * 'RSA-OAEP-256' key and 'A256GCM' content encryption algorithms will be used
     * unless different ones have been set with {@code JwtEncryptionBuilder}.
     * A key of size 2048 bits or larger MUST be used with the 'RSA-OAEP' and 'RSA-OAEP-256' algorithms.
     *
     * @param keyEncryptionKey the key which encrypts the content encryption key
     * @return encrypted JWT token
     * @throws JwtEncryptionException the exception if the encryption operation has failed
     */
    String encrypt(SecretKey keyEncryptionKey) throws JwtEncryptionException;

    /**
     * Encrypt the claims or inner JWT with a public or secret key loaded from the custom location
     * which can point to a PEM, JWK or JWK set keys.
     * 'RSA-OAEP-256' key and 'A256GCM' content encryption algorithms will be used
     * unless different ones have been set with {@code JwtEncryptionBuilder}.
     * A key of size 2048 bits or larger MUST be used with the 'RSA-OAEP' and 'RSA-OAEP-256' algorithms.
     *
     * @param keyLocation the location of the keyEncryptionKey which encrypts the content encryption key
     * @return encrypted JWT token
     * @throws JwtEncryptionException the exception if the encryption operation has failed
     */
    String encrypt(String keyLocation) throws JwtEncryptionException;

    /**
     * Encrypt the claims or inner JWT with a key loaded from the location set with the
     * "smallrye.jwt.encrypt.key-location" property.
     * 'RSA-OAEP-256' key and 'A256GCM' content encryption algorithms will be used
     * unless different ones have been set with {@code JwtEncryptionBuilder}.
     * A key of size 2048 bits or larger MUST be used with the 'RSA-OAEP' and 'RSA-OAEP-256' algorithms.
     *
     * @return encrypted JWT token
     * @throws JwtEncryptionException the exception if the encryption operation has failed
     */
    String encrypt() throws JwtEncryptionException;

}
