package io.smallrye.jwt.algorithm;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Set;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;

/**
 * JWS signer for EdDSA (Ed25519/Ed448) using JCA, no Tink dependency.
 */
public class EdDSASigner implements JWSSigner {

    private static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS = Set.of(JWSAlgorithm.EdDSA);

    private final PrivateKey privateKey;
    private final JCAContext jcaContext = new JCAContext();

    public EdDSASigner(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    @Override
    public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
        try {
            Signature sig = Signature.getInstance(privateKey.getAlgorithm());
            sig.initSign(privateKey);
            sig.update(signingInput);
            return Base64URL.encode(sig.sign());
        } catch (Exception e) {
            throw new JOSEException("EdDSA signing failed: " + e.getMessage(), e);
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
     * Converts an EdDSA (Ed25519/Ed448) {@link OctetKeyPair} private JWK into a JCA {@link PrivateKey},
     * avoiding the Tink dependency Nimbus relies on for {@code OctetKeyPair.toPrivateKey()}.
     */
    public static PrivateKey toPrivateKey(OctetKeyPair okp) throws JOSEException {
        try {
            String curveName = okp.getCurve().getName();
            String jcaAlg = "Ed25519".equals(curveName) ? "Ed25519"
                    : "Ed448".equals(curveName) ? "Ed448" : curveName;
            byte[] dBytes = okp.getDecodedD();

            NamedParameterSpec paramSpec = new NamedParameterSpec(jcaAlg);
            EdECPrivateKeySpec keySpec = new EdECPrivateKeySpec(paramSpec, dBytes);
            KeyFactory kf = KeyFactory.getInstance(jcaAlg);
            return kf.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new JOSEException("Failed to convert EdDSA JWK to a private key: " + e.getMessage(), e);
        }
    }
}
