package io.smallrye.jwk;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;

/**
 * A JSON Web Key representing an elliptic curve key.
 */
public class EcJsonWebKey extends AsymmetricJsonWebKey {

    EcJsonWebKey(ECKey jwk) {
        super(jwk);
    }

    /**
     * Create a builder of a JSON Web Key representing a newly generated EC key pair.
     *
     * @param curve the curve of the generated key
     * @return the JSON Web Key builder
     */
    public static Builder builder(EcCurve curve) {
        return new Builder(curve);
    }

    /**
     * Create a builder of a JSON Web Key representing the given EC public key.
     *
     * @param publicKey the EC public key
     * @return the JSON Web Key builder
     */
    public static Builder builder(ECPublicKey publicKey) {
        return new Builder(publicKey);
    }

    @Override
    public ECPublicKey publicKey() throws JsonWebKeyException {
        return (ECPublicKey) super.publicKey();
    }

    @Override
    public ECPrivateKey privateKey() throws JsonWebKeyException {
        return (ECPrivateKey) super.privateKey();
    }

    /**
     * The `crv` curve of this key.
     *
     * @return the curve name, for example, `P-256`
     */
    public String curve() {
        return ((ECKey) jwk()).getCurve().getName();
    }

    /**
     * A builder of a JSON Web Key representing an elliptic curve key.
     */
    public static class Builder extends AsymmetricJsonWebKey.Builder<EcJsonWebKey> {

        private final EcCurve curve;
        private final ECPublicKey publicKey;

        private Builder(EcCurve curve) {
            this.curve = curve;
            this.publicKey = null;
        }

        private Builder(ECPublicKey publicKey) {
            this.curve = null;
            this.publicKey = publicKey;
        }

        @Override
        public EcJsonWebKey build() throws JsonWebKeyException {
            return new EcJsonWebKey((ECKey) buildJwk());
        }

        @Override
        JWK keyJwk() throws JsonWebKeyException {
            if (publicKey != null) {
                Curve keyCurve = Curve.forECParameterSpec(publicKey.getParams());
                if (keyCurve == null) {
                    throw new JsonWebKeyException("Unsupported EC public key curve");
                }
                return new ECKey.Builder(keyCurve, publicKey).build();
            }
            try {
                return new ECKeyGenerator(Curve.parse(curve.getName())).generate();
            } catch (JOSEException ex) {
                throw new JsonWebKeyException("Failed to generate an EC key pair: " + ex.getMessage(), ex);
            }
        }
    }
}
