package io.smallrye.jwt.algorithm;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.XECPrivateKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.util.Set;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.CriticalHeaderParamsAware;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.impl.CriticalHeaderParamsDeferral;
import com.nimbusds.jose.crypto.impl.ECDHCryptoProvider;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;

/**
 * JWE decrypter for X25519 and X448 key agreement using JCA (no Tink dependency).
 */
public class XDHDecrypter extends ECDHCryptoProvider implements JWEDecrypter, CriticalHeaderParamsAware {

    private static final Set<Curve> SUPPORTED_CURVES = Set.of(Curve.X25519, Curve.X448);

    private final PrivateKey privateKey;
    private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();

    public XDHDecrypter(PrivateKey privateKey, Curve curve) throws JOSEException {
        super(curve, null);
        this.privateKey = privateKey;
    }

    /**
     * Creates an XDHDecrypter from an XECPrivateKey, automatically determining the curve.
     */
    public static XDHDecrypter fromXECPrivateKey(XECPrivateKey xecKey) throws JOSEException {
        NamedParameterSpec params = (NamedParameterSpec) xecKey.getParams();
        Curve curve = "X25519".equals(params.getName()) ? Curve.X25519 : Curve.X448;
        return new XDHDecrypter(xecKey, curve);
    }

    @Override
    public Set<Curve> supportedEllipticCurves() {
        return SUPPORTED_CURVES;
    }

    @Override
    public Set<String> getProcessedCriticalHeaderParams() {
        return critPolicy.getProcessedCriticalHeaderParams();
    }

    @Override
    public Set<String> getDeferredCriticalHeaderParams() {
        return critPolicy.getDeferredCriticalHeaderParams();
    }

    @Override
    public byte[] decrypt(JWEHeader header, Base64URL encryptedKey, Base64URL iv,
            Base64URL cipherText, Base64URL authTag, byte[] aad) throws JOSEException {
        // unsupported critical headers must be rejected, as Nimbus decrypters and jose4j do
        critPolicy.ensureHeaderPasses(header);
        try {
            OctetKeyPair ephemeralJwk = (OctetKeyPair) header.getEphemeralPublicKey();
            if (ephemeralJwk == null) {
                throw new JOSEException("Missing ephemeral public key in JWE header");
            }
            if (!getCurve().equals(ephemeralJwk.getCurve())) {
                throw new JOSEException("Curve of ephemeral public key does not match curve of private key");
            }

            PublicKey ephemeralPublicKey = XDHEncrypter.octetKeyPairToXecPublicKey(ephemeralJwk);

            KeyAgreement ka = KeyAgreement.getInstance("XDH");
            ka.init(privateKey);
            ka.doPhase(ephemeralPublicKey, true);
            SecretKey Z = new SecretKeySpec(ka.generateSecret(), "AES");

            return decryptWithZ(header, aad, Z, encryptedKey, iv, cipherText, authTag);
        } catch (JOSEException e) {
            throw e;
        } catch (Exception e) {
            throw new JOSEException("XDH decryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * Converts an XDH (X25519/X448) {@link OctetKeyPair} private JWK into a JCA {@link PrivateKey},
     * Nimbus {@code OctetKeyPair.toPrivateKey()} does not support it.
     */
    public static PrivateKey toPrivateKey(OctetKeyPair okp) throws JOSEException {
        try {
            // `d` is the raw little-endian scalar, as XECPrivateKeySpec expects
            XECPrivateKeySpec keySpec = new XECPrivateKeySpec(new NamedParameterSpec(okp.getCurve().getName()),
                    okp.getDecodedD());
            return KeyFactory.getInstance("XDH").generatePrivate(keySpec);
        } catch (Exception e) {
            throw new JOSEException("Failed to convert XDH JWK to a private key: " + e.getMessage(), e);
        }
    }
}
