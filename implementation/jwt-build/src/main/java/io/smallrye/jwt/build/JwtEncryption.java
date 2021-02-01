package io.smallrye.jwt.build;

import java.security.PublicKey;

import javax.crypto.SecretKey;

/**
 * JWT JsonWebEncryption.
 */
public interface JwtEncryption {

    /**
     * Encrypt the claims or inner JWT with {@link PublicKey}.
     * 'RSA-OAEP-256' and 'ECDH-ES+A256KW' key encryption algorithms will be used by default
     * when public RSA or EC keys are used unless a different one has been set with {@code JwtEncryptionBuilder}.
     * 'A256GCM' content encryption algorithms will be used unless a different one have been set with
     * {@code JwtEncryptionBuilder}.
     * A key of size 2048 bits or larger MUST be used with the 'RSA-OAEP' and 'RSA-OAEP-256' algorithms.
     *
     * Note: Setting 'RSA-OAEP-256' as a default key encryption algorithm when public RSA keys are used is deprecated.
     * Future version of this API will set 'RSA-OAEP' by default.
     *
     * @param keyEncryptionKey the key which encrypts the content encryption key
     * @return encrypted JWT token
     * @throws JwtEncryptionException the exception if the encryption operation has failed
     */
    String encrypt(PublicKey keyEncryptionKey) throws JwtEncryptionException;

    /**
     * Encrypt the claims or inner JWT with {@link SecretKey}.
     * 'A256KW' key and 'A256GCM' content encryption algorithms will be used
     * unless different ones have been set with {@code JwtEncryptionBuilder}.
     *
     * @param keyEncryptionKey the key which encrypts the content encryption key
     * @return encrypted JWT token
     * @throws JwtEncryptionException the exception if the encryption operation has failed
     */
    String encrypt(SecretKey keyEncryptionKey) throws JwtEncryptionException;

    /**
     * Encrypt the claims or inner JWT with a public or secret key loaded from the custom location
     * which can point to a PEM, JWK or JWK set keys.
     * 'RSA-OAEP-256', 'ECDH-ES+A256KW' and 'A256KW' key encryption algorithms will be used by default
     * when public RSA, EC or secret keys are used unless a different one has been set with {@code JwtEncryptionBuilder}.
     * 'A256GCM' content encryption algorithms will be used unless a different one have been set with
     * {@code JwtEncryptionBuilder}.
     * A key of size 2048 bits or larger MUST be used with the 'RSA-OAEP' and 'RSA-OAEP-256' algorithms.
     *
     * Note: Setting 'RSA-OAEP-256' as a default key encryption algorithm when public RSA keys are used is deprecated.
     * Future version of this API will set 'RSA-OAEP' by default.
     *
     * @param keyLocation the location of the keyEncryptionKey which encrypts the content encryption key
     * @return encrypted JWT token
     * @throws JwtEncryptionException the exception if the encryption operation has failed
     */
    String encrypt(String keyLocation) throws JwtEncryptionException;

    /**
     * Encrypt the claims or inner JWT with a key loaded from the location set with the
     * "smallrye.jwt.encrypt.key-location" or "smallrye.jwt.encrypt.key.location" properties.
     * 
     * Note: "smallrye.jwt.encrypt.key-location" property is deprecated and will be removed in the next major release.
     * 
     * 'RSA-OAEP-256', 'ECDH-ES+A256KW' and 'A256KW' key encryption algorithms will be used by default
     * when public RSA, EC or secret keys are used unless a different one has been set with {@code JwtEncryptionBuilder}.
     * 'A256GCM' content encryption algorithms will be used unless a different one have been set with
     * {@code JwtEncryptionBuilder}.
     * A key of size 2048 bits or larger MUST be used with the 'RSA-OAEP' and 'RSA-OAEP-256' algorithms.
     *
     * Note: Setting 'RSA-OAEP-256' as a default key encryption algorithm when public RSA keys are used is deprecated.
     * Future version of this API will set 'RSA-OAEP' by default.
     *
     * @return encrypted JWT token
     * @throws JwtEncryptionException the exception if the encryption operation has failed
     */
    String encrypt() throws JwtEncryptionException;

    /**
     * Encrypt the claims or inner JWT with a secret key string.
     * 'A256KW' key encryption algorithms will be used by default unless a different one has been set with
     * {@code JwtEncryptionBuilder}.
     * 'A256GCM' content encryption algorithms will be used unless a different one have been set with
     * {@code JwtEncryptionBuilder}.
     *
     * @param secret the secret
     * @return encrypted JWT token
     * @throws JwtEncryptionException the exception if the encryption operation has failed
     */
    String encryptWithSecret(String secret) throws JwtEncryptionException;
}
