package io.smallrye.jwk;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

/**
 * A JSON Web Key representing an RSA key.
 */
public class RsaJsonWebKey extends AsymmetricJsonWebKey {

    RsaJsonWebKey(RSAKey jwk) {
        super(jwk);
    }

    /**
     * Create a builder of a JSON Web Key representing a newly generated RSA key pair.
     *
     * @param keySize the size of the generated key in bits, at least 2048
     * @return the JSON Web Key builder
     */
    public static Builder builder(int keySize) {
        return new Builder(keySize);
    }

    /**
     * Create a builder of a JSON Web Key representing the given RSA public key.
     *
     * @param publicKey the RSA public key
     * @return the JSON Web Key builder
     */
    public static Builder builder(RSAPublicKey publicKey) {
        return new Builder(publicKey);
    }

    @Override
    public RSAPublicKey publicKey() throws JsonWebKeyException {
        return (RSAPublicKey) super.publicKey();
    }

    @Override
    public RSAPrivateKey privateKey() throws JsonWebKeyException {
        return (RSAPrivateKey) super.privateKey();
    }

    /**
     * A builder of a JSON Web Key representing an RSA key.
     */
    public static class Builder extends AsymmetricJsonWebKey.Builder<RsaJsonWebKey> {

        private final int keySize;
        private final RSAPublicKey publicKey;

        private Builder(int keySize) {
            this.keySize = keySize;
            this.publicKey = null;
        }

        private Builder(RSAPublicKey publicKey) {
            this.keySize = 0;
            this.publicKey = publicKey;
        }

        @Override
        public RsaJsonWebKey build() throws JsonWebKeyException {
            return new RsaJsonWebKey((RSAKey) buildJwk());
        }

        @Override
        JWK keyJwk() throws JsonWebKeyException {
            if (publicKey != null) {
                return new RSAKey.Builder(publicKey).build();
            }
            try {
                return new RSAKeyGenerator(keySize).generate();
            } catch (JOSEException ex) {
                throw new JsonWebKeyException("Failed to generate an RSA key pair: " + ex.getMessage(), ex);
            }
        }
    }
}
