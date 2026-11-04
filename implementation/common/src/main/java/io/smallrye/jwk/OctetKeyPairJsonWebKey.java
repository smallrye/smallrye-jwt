package io.smallrye.jwk;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.EdECPoint;
import java.util.Arrays;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;

import io.smallrye.jwt.algorithm.EdDSASigner;
import io.smallrye.jwt.algorithm.EdDSAVerifier;
import io.smallrye.jwt.algorithm.XDHDecrypter;
import io.smallrye.jwt.algorithm.XDHEncrypter;

/**
 * A JSON Web Key representing an Octet Key Pair (OKP): an EdDSA (Ed25519/Ed448) signature key
 * or an XDH (X25519/X448) key agreement key.
 */
public class OctetKeyPairJsonWebKey extends AsymmetricJsonWebKey {

    OctetKeyPairJsonWebKey(OctetKeyPair jwk) {
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
     * Create a builder of a JSON Web Key representing the given EdDSA or XDH public key.
     *
     * @param publicKey the EdDSA or XDH public key
     * @return the JSON Web Key builder
     */
    public static Builder builder(PublicKey publicKey) {
        return new Builder(publicKey);
    }

    @Override
    public PublicKey publicKey() throws JsonWebKeyException {
        try {
            // Nimbus does not support exporting an OKP as a java.security.PublicKey
            return isXdh() ? XDHEncrypter.toPublicKey(key()) : EdDSAVerifier.toPublicKey(key());
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
            return isXdh() ? XDHDecrypter.toPrivateKey(key()) : EdDSASigner.toPrivateKey(key());
        } catch (JOSEException ex) {
            throw new JsonWebKeyException("Failed to create a private key from the JSON Web Key: " + ex.getMessage(), ex);
        }
    }

    /**
     * The `crv` curve of this key.
     *
     * @return the curve name, for example, `Ed25519` or `X25519`
     */
    public String curve() {
        return key().getCurve().getName();
    }

    private OctetKeyPair key() {
        return (OctetKeyPair) jwk();
    }

    // The key conversion depends on the curve, as in jose4j OctetKeyPairJsonWebKey
    private boolean isXdh() {
        Curve curve = key().getCurve();
        return Curve.X25519.equals(curve) || Curve.X448.equals(curve);
    }

    /**
     * A builder of a JSON Web Key representing an Edwards curve key.
     */
    public static class Builder extends AsymmetricJsonWebKey.Builder<OctetKeyPairJsonWebKey> {

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
        public OctetKeyPairJsonWebKey build() throws JsonWebKeyException {
            return new OctetKeyPairJsonWebKey((OctetKeyPair) buildJwk());
        }

        @Override
        JWK keyJwk() throws JsonWebKeyException {
            if (publicKey != null) {
                return toJwk(publicKey);
            }
            // Nimbus OctetKeyPairGenerator requires Tink and does not support Ed448, use JCA instead
            try {
                KeyPair keyPair = KeyPairGenerator.getInstance(curve.getName()).generateKeyPair();
                OctetKeyPair publicJwk = (OctetKeyPair) toJwk(keyPair.getPublic());
                byte[] d = ((EdECPrivateKey) keyPair.getPrivate()).getBytes().orElseThrow();
                return new OctetKeyPair.Builder(publicJwk).d(Base64URL.encode(d)).build();
            } catch (GeneralSecurityException ex) {
                throw new JsonWebKeyException("Failed to generate an EdDSA key pair: " + ex.getMessage(), ex);
            }
        }

        private static JWK toJwk(PublicKey key) throws JsonWebKeyException {
            if (key instanceof XECPublicKey) {
                try {
                    return XDHEncrypter.toOctetKeyPair((XECPublicKey) key);
                } catch (JOSEException ex) {
                    throw new JsonWebKeyException("Failed to create an XDH JSON Web Key: " + ex.getMessage(), ex);
                }
            }
            if (!(key instanceof EdECPublicKey)) {
                throw new JsonWebKeyException("Unsupported EdDSA public key: " + key.getAlgorithm());
            }
            // As in jose4j, the curve and the raw key bytes come from the EdEC key itself
            EdECPublicKey edEcKey = (EdECPublicKey) key;
            boolean ed25519 = EdDsaCurve.ED25519.getName().equals(edEcKey.getParams().getName());
            EdECPoint point = edEcKey.getPoint();
            // The raw key is the little-endian y coordinate, with the x-odd bit set in the last byte
            byte[] rawBytes = Arrays.copyOf(reverse(point.getY().toByteArray()), ed25519 ? 32 : 57);
            if (point.isXOdd()) {
                rawBytes[rawBytes.length - 1] |= (byte) 0x80;
            }
            return new OctetKeyPair.Builder(ed25519 ? Curve.Ed25519 : Curve.Ed448, Base64URL.encode(rawBytes)).build();
        }

        private static byte[] reverse(byte[] in) {
            byte[] out = new byte[in.length];
            for (int i = 0; i < in.length; i++) {
                out[i] = in[in.length - 1 - i];
            }
            return out;
        }
    }
}
