package io.smallrye.jwk;

import java.security.PrivateKey;
import java.security.PublicKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.util.Base64URL;

import io.smallrye.jwt.algorithm.EdDSASigner;
import io.smallrye.jwt.algorithm.EdDSAVerifier;

/**
 * A JSON Web Key representing an Edwards curve key.
 */
public class EdDsaJsonWebKey extends AsymmetricJsonWebKey {

    EdDsaJsonWebKey(OctetKeyPair jwk) {
        super(jwk);
    }

    /**
     * Create a builder of a JSON Web Key representing a newly generated EdDSA key pair.
     *
     * @param curve the curve of the generated key
     * @return the JSON Web Key builder
     */
    public static Builder builder(EdDsaCurve curve) {
        return new Builder(curve);
    }

    /**
     * Create a builder of a JSON Web Key representing the given EdDSA public key.
     *
     * @param publicKey the EdDSA public key
     * @return the JSON Web Key builder
     */
    public static Builder builder(PublicKey publicKey) {
        return new Builder(publicKey);
    }

    @Override
    public PublicKey publicKey() throws JsonWebKeyException {
        try {
            // Nimbus does not support exporting an OKP as a java.security.PublicKey
            return EdDSAVerifier.toPublicKey(key());
        } catch (JOSEException ex) {
            throw new JsonWebKeyException("Failed to create a public key from the JSON Web Key: " + ex.getMessage(), ex);
        }
    }

    @Override
    public PrivateKey privateKey() throws JsonWebKeyException {
        if (key().getD() == null) {
            return null;
        }
        try {
            // Nimbus does not support exporting an OKP as a java.security.PrivateKey
            return EdDSASigner.toPrivateKey(key());
        } catch (JOSEException ex) {
            throw new JsonWebKeyException("Failed to create a private key from the JSON Web Key: " + ex.getMessage(), ex);
        }
    }

    /**
     * The `crv` curve of this key.
     *
     * @return the curve name, for example, `Ed25519`
     */
    public String curve() {
        return key().getCurve().getName();
    }

    private OctetKeyPair key() {
        return (OctetKeyPair) jwk();
    }

    /**
     * A builder of a JSON Web Key representing an Edwards curve key.
     */
    public static class Builder extends AsymmetricJsonWebKey.Builder<EdDsaJsonWebKey> {

        private final EdDsaCurve curve;
        private final PublicKey publicKey;

        private Builder(EdDsaCurve curve) {
            this.curve = curve;
            this.publicKey = null;
        }

        private Builder(PublicKey publicKey) {
            this.curve = null;
            this.publicKey = publicKey;
        }

        @Override
        public EdDsaJsonWebKey build() throws JsonWebKeyException {
            return new EdDsaJsonWebKey((OctetKeyPair) buildJwk());
        }

        @Override
        JWK keyJwk() throws JsonWebKeyException {
            if (publicKey != null) {
                return toJwk(publicKey);
            }
            try {
                return new OctetKeyPairGenerator(Curve.parse(curve.getName())).generate();
            } catch (JOSEException ex) {
                throw new JsonWebKeyException("Failed to generate an EdDSA key pair: " + ex.getMessage(), ex);
            }
        }

        private static JWK toJwk(PublicKey key) throws JsonWebKeyException {
            String alg = key.getAlgorithm();
            Curve curve;
            if (EdDsaCurve.ED25519.getName().equals(alg)) {
                curve = Curve.Ed25519;
            } else if (EdDsaCurve.ED448.getName().equals(alg)) {
                curve = Curve.Ed448;
            } else if ("EdDSA".equals(alg)) {
                // Detect curve from encoded key length: Ed25519=44, Ed448=69
                curve = key.getEncoded().length <= 50 ? Curve.Ed25519 : Curve.Ed448;
            } else {
                throw new JsonWebKeyException("Unsupported EdDSA algorithm: " + alg);
            }

            // The X.509 SubjectPublicKeyInfo for EdDSA wraps the raw public key in a
            // BIT STRING inside a SEQUENCE with an AlgorithmIdentifier.
            // The raw key bytes are after the ASN.1 header.
            // Rather than parsing ASN.1, use the key's encoded bytes and strip the header.
            byte[] encoded = key.getEncoded();
            // The last N bytes are the raw public key (32 for Ed25519, 57 for Ed448)
            int rawLen = curve == Curve.Ed25519 ? 32 : 57;
            if (encoded.length < rawLen) {
                throw new JsonWebKeyException("Encoded key too short");
            }
            byte[] rawBytes = new byte[rawLen];
            System.arraycopy(encoded, encoded.length - rawLen, rawBytes, 0, rawLen);

            return new OctetKeyPair.Builder(curve, Base64URL.encode(rawBytes)).build();
        }
    }
}
