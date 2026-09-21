package io.smallrye.jwt.algorithm;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Set;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.impl.ECDHCryptoProvider;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;

/**
 * JWE decrypter for X25519 and X448 key agreement using JCA (no Tink dependency).
 */
public class XDHDecrypter extends ECDHCryptoProvider implements JWEDecrypter {

    private static final Set<Curve> SUPPORTED_CURVES = Set.of(Curve.X25519, Curve.X448);

    private final PrivateKey privateKey;

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
    public byte[] decrypt(JWEHeader header, Base64URL encryptedKey, Base64URL iv,
            Base64URL cipherText, Base64URL authTag, byte[] aad) throws JOSEException {
        try {
            OctetKeyPair ephemeralJwk = (OctetKeyPair) header.getEphemeralPublicKey();
            if (ephemeralJwk == null) {
                throw new JOSEException("Missing ephemeral public key in JWE header");
            }

            PublicKey ephemeralPublicKey = octetKeyPairToXecPublicKey(ephemeralJwk);

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

    private static XECPublicKey octetKeyPairToXecPublicKey(OctetKeyPair okp) throws Exception {
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
