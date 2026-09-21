package io.smallrye.jwt.algorithm;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Set;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;

/**
 * JWS verifier for EdDSA (Ed25519/Ed448) using JCA, no Tink dependency.
 */
public class EdDSAVerifier implements JWSVerifier {

    private static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS = Set.of(JWSAlgorithm.EdDSA);

    private final PublicKey publicKey;
    private final JCAContext jcaContext = new JCAContext();

    public EdDSAVerifier(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public boolean verify(JWSHeader header, byte[] signingInput, Base64URL signature) throws JOSEException {
        try {
            Signature sig = Signature.getInstance(publicKey.getAlgorithm());
            sig.initVerify(publicKey);
            sig.update(signingInput);
            return sig.verify(signature.decode());
        } catch (Exception e) {
            throw new JOSEException("EdDSA verification failed: " + e.getMessage(), e);
        }
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return SUPPORTED_ALGORITHMS;
    }

    @Override
    public JCAContext getJCAContext() {
        return jcaContext;
    }

    /**
     * Converts an EdDSA (Ed25519/Ed448) {@link OctetKeyPair} public JWK into a JCA {@link PublicKey},
     * avoiding the Tink dependency Nimbus relies on for {@code OctetKeyPair.toPublicKey()}.
     */
    public static PublicKey toPublicKey(OctetKeyPair okp) throws JOSEException {
        try {
            String curveName = okp.getCurve().getName();
            String jcaAlg = "Ed25519".equals(curveName) ? "Ed25519"
                    : "Ed448".equals(curveName) ? "Ed448" : curveName;
            byte[] xBytes = okp.getDecodedX();

            NamedParameterSpec paramSpec = new NamedParameterSpec(jcaAlg);
            byte[] reversed = new byte[xBytes.length];
            for (int i = 0; i < xBytes.length; i++) {
                reversed[i] = xBytes[xBytes.length - 1 - i];
            }
            boolean xOdd = (reversed[0] & 0x80) != 0;
            reversed[0] &= 0x7F;
            BigInteger y = new BigInteger(1, reversed);
            EdECPoint point = new EdECPoint(xOdd, y);
            EdECPublicKeySpec keySpec = new EdECPublicKeySpec(paramSpec, point);
            KeyFactory kf = KeyFactory.getInstance(jcaAlg);
            return kf.generatePublic(keySpec);
        } catch (Exception e) {
            throw new JOSEException("Failed to convert EdDSA JWK to a public key: " + e.getMessage(), e);
        }
    }
}
