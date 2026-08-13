package io.smallrye.jwt.algorithm;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;
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
 * The u-coordinate encoding/decoding follows RFC 7748 and jose4j's XDHKeyUtil approach.
 */
public class XDHEncrypter extends ECDHCryptoProvider implements JWEEncrypter {

    private static final Set<Curve> SUPPORTED_CURVES = Set.of(Curve.X25519, Curve.X448);

    // 2^255 - 19
    private static final BigInteger P_X25519 = new BigInteger(
            "57896044618658097711785492504343953926634992332820282019728792003956564819949");
    // 2^448 - 2^224 - 1
    private static final BigInteger P_X448 = new BigInteger(
            "726838724295606890549323807888004534353641360687318060281490199180612328166730"
                    + "772686396383698676545930088884461843637361053498018365439");

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

    static OctetKeyPair xecPublicKeyToOctetKeyPair(XECPublicKey xecKey, Curve curve) {
        BigInteger u = xecKey.getU();
        boolean is25519 = Curve.X25519.equals(curve);
        u = u.mod(is25519 ? P_X25519 : P_X448);
        byte[] littleEndian = reverse(u.toByteArray());
        int byteLen = is25519 ? 32 : 57;
        if (littleEndian.length != byteLen) {
            littleEndian = Arrays.copyOf(littleEndian, byteLen);
        }
        return new OctetKeyPair.Builder(curve, Base64URL.encode(littleEndian)).build();
    }

    static XECPublicKey octetKeyPairToXecPublicKey(OctetKeyPair okp) throws Exception {
        String curveName = okp.getCurve().getName();
        byte[] littleEndian = okp.getDecodedX();
        byte[] bigEndian = reverse(littleEndian);

        int numBits = "X25519".equals(curveName) ? 255 : 448;
        int numBitsMod8 = numBits % 8;
        if (numBitsMod8 != 0) {
            int andMask = (1 << numBitsMod8) - 1;
            bigEndian[0] &= andMask;
        }

        BigInteger u = new BigInteger(1, bigEndian);
        XECPublicKeySpec keySpec = new XECPublicKeySpec(new NamedParameterSpec(curveName), u);
        KeyFactory kf = KeyFactory.getInstance("XDH");
        return (XECPublicKey) kf.generatePublic(keySpec);
    }

    private static byte[] reverse(byte[] in) {
        byte[] reversed = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            reversed[reversed.length - 1 - i] = in[i];
        }
        return reversed;
    }
}
