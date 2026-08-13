package io.smallrye.jwt.algorithm;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Set;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWECryptoParts;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.impl.AAD;
import com.nimbusds.jose.crypto.impl.ECDHCryptoProvider;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;

/**
 * JWE encrypter for X25519 and X448 key agreement using JCA (no Tink dependency).
 * The public key u-coordinate is encoded and decoded as specified in RFC 7748, section 5.
 */
public class XDHEncrypter extends ECDHCryptoProvider implements JWEEncrypter {

    private static final Set<Curve> SUPPORTED_CURVES = Set.of(Curve.X25519, Curve.X448);

    private final PublicKey publicKey;

    public XDHEncrypter(PublicKey publicKey, Curve curve) throws JOSEException {
        super(curve, null);
        this.publicKey = publicKey;
    }

    /**
     * Detect the XEC curve (X25519 or X448) from a public key.
     */
    public static Curve detectCurve(PublicKey key) throws JOSEException {
        try {
            XECPublicKey xecKey = (XECPublicKey) key;
            NamedParameterSpec params = (NamedParameterSpec) xecKey.getParams();
            String name = params.getName();
            return "X25519".equals(name) ? Curve.X25519 : Curve.X448;
        } catch (Exception e) {
            throw new JOSEException("Failed to detect XEC curve from key: " + e.getMessage(), e);
        }
    }

    @Override
    public Set<Curve> supportedEllipticCurves() {
        return SUPPORTED_CURVES;
    }

    @Override
    public JWECryptoParts encrypt(JWEHeader header, byte[] clearText, byte[] aad) throws JOSEException {
        try {
            String curveName = getCurve().getName();
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
            kpg.initialize(new NamedParameterSpec(curveName));
            KeyPair ephemeral = kpg.generateKeyPair();

            KeyAgreement ka = KeyAgreement.getInstance("XDH");
            ka.init(ephemeral.getPrivate());
            ka.doPhase(publicKey, true);
            SecretKey Z = new SecretKeySpec(ka.generateSecret(), "AES");

            OctetKeyPair ephemeralJwk = xecPublicKeyToOctetKeyPair(
                    (XECPublicKey) ephemeral.getPublic(), getCurve());

            JWEHeader updatedHeader = new JWEHeader.Builder(header)
                    .ephemeralPublicKey(ephemeralJwk)
                    .build();

            return encryptWithZ(updatedHeader, Z, clearText, AAD.compute(updatedHeader));
        } catch (JOSEException e) {
            throw e;
        } catch (Exception e) {
            throw new JOSEException("XDH encryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * Converts an XDH (X25519/X448) {@link XECPublicKey} into an {@link OctetKeyPair} public JWK.
     */
    public static OctetKeyPair toOctetKeyPair(XECPublicKey xecKey) throws JOSEException {
        return xecPublicKeyToOctetKeyPair(xecKey, detectCurve(xecKey));
    }

    static OctetKeyPair xecPublicKeyToOctetKeyPair(XECPublicKey xecKey, Curve curve) {
        // RFC 7748, section 5: the u-coordinate is encoded as a little-endian array of 32 (X25519)
        // or 56 (X448) bytes; RFC 8037, section 3.2: the JWK 'x' is the base64url of this encoding
        byte[] bigEndian = xecKey.getU().toByteArray();
        byte[] littleEndian = new byte[rawKeyLength(curve)];
        for (int i = 0; i < bigEndian.length && i < littleEndian.length; i++) {
            littleEndian[i] = bigEndian[bigEndian.length - 1 - i];
        }
        return new OctetKeyPair.Builder(curve, Base64URL.encode(littleEndian)).build();
    }

    /**
     * Converts an XDH (X25519/X448) {@link OctetKeyPair} public JWK into a JCA {@link PublicKey},
     * Nimbus {@code OctetKeyPair.toPublicKey()} does not support it.
     */
    public static PublicKey toPublicKey(OctetKeyPair okp) throws JOSEException {
        try {
            return octetKeyPairToXecPublicKey(okp);
        } catch (Exception e) {
            throw new JOSEException("Failed to convert XDH JWK to a public key: " + e.getMessage(), e);
        }
    }

    static XECPublicKey octetKeyPairToXecPublicKey(OctetKeyPair okp) throws Exception {
        Curve curve = okp.getCurve();
        byte[] littleEndian = okp.getDecodedX();
        byte[] bigEndian = new byte[littleEndian.length];
        for (int i = 0; i < littleEndian.length; i++) {
            bigEndian[i] = littleEndian[littleEndian.length - 1 - i];
        }
        if (Curve.X25519.equals(curve)) {
            // RFC 7748, section 5: the most significant bit of the last X25519 byte is ignored
            bigEndian[0] &= 0x7F;
        }
        BigInteger u = new BigInteger(1, bigEndian);
        XECPublicKeySpec keySpec = new XECPublicKeySpec(new NamedParameterSpec(curve.getName()), u);
        return (XECPublicKey) KeyFactory.getInstance("XDH").generatePublic(keySpec);
    }

    private static int rawKeyLength(Curve curve) {
        return Curve.X25519.equals(curve) ? 32 : 56;
    }
}
