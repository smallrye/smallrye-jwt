package io.smallrye.jwk;

import java.security.PrivateKey;
import java.security.PublicKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;

/**
 * A JSON Web Key representing an asymmetric key, which always has a public key
 * and may also have a private key.
 */
public abstract class AsymmetricJsonWebKey extends JsonWebKey {

    AsymmetricJsonWebKey(JWK jwk) {
        super(jwk);
    }

    /**
     * The public key this JSON Web Key represents.
     *
     * @return the public key
     * @throws JsonWebKeyException if the public key can not be created
     */
    public PublicKey publicKey() throws JsonWebKeyException {
        try {
            return ((AsymmetricJWK) jwk()).toPublicKey();
        } catch (JOSEException ex) {
            throw new JsonWebKeyException("Failed to create a public key from the JSON Web Key: " + ex.getMessage(), ex);
        }
    }

    /**
     * The private key this JSON Web Key represents.
     *
     * @return the private key, or null if this JSON Web Key has the public key only
     * @throws JsonWebKeyException if the private key can not be created
     */
    public PrivateKey privateKey() throws JsonWebKeyException {
        try {
            return ((AsymmetricJWK) jwk()).toPrivateKey();
        } catch (JOSEException ex) {
            throw new JsonWebKeyException("Failed to create a private key from the JSON Web Key: " + ex.getMessage(), ex);
        }
    }

    /**
     * A builder of an asymmetric JSON Web Key.
     *
     * @param <T> the type of the JSON Web Key this builder creates
     */
    public abstract static class Builder<T extends AsymmetricJsonWebKey> extends JsonWebKey.Builder {

        Builder() {
        }

        /**
         * Set the `kid` key identifier.
         *
         * @param keyId the key identifier
         * @return this builder
         */
        public Builder<T> keyId(String keyId) {
            return property("kid", keyId);
        }

        /**
         * Set the `use` public key use.
         *
         * @param keyUse the public key use
         * @return this builder
         */
        public Builder<T> keyUse(String keyUse) {
            return property("use", keyUse);
        }

        /**
         * Set the `alg` algorithm this key is intended to be used with.
         *
         * @param algorithm the algorithm
         * @return this builder
         */
        public Builder<T> algorithm(String algorithm) {
            return property("alg", algorithm);
        }

        /**
         * Set a JSON Web Key property.
         *
         * @param name the property name
         * @param value the property value
         * @return this builder
         */
        public Builder<T> property(String name, String value) {
            putProperty(name, value);
            return this;
        }

        @Override
        public abstract T build() throws JsonWebKeyException;
    }
}
