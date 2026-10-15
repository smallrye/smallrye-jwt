package io.smallrye.jwk;

import javax.crypto.SecretKey;

import com.nimbusds.jose.jwk.OctetSequenceKey;

/**
 * A JSON Web Key representing a symmetric secret key.
 */
public class SecretJsonWebKey extends JsonWebKey {

    private static final String SECRET_KEY_ALGORITHM = "AES";

    SecretJsonWebKey(OctetSequenceKey jwk) {
        super(jwk);
    }

    /**
     * The secret key this JSON Web Key represents.
     *
     * @return the secret key
     */
    public SecretKey secretKey() {
        return ((OctetSequenceKey) jwk()).toSecretKey(SECRET_KEY_ALGORITHM);
    }
}
