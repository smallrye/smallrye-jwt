package io.smallrye.jwt.build.impl;

import java.io.IOException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.eclipse.microprofile.config.ConfigProvider;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;

import io.smallrye.jwt.common.JwtClaims;
import io.smallrye.jwt.util.KeyUtils;
import io.smallrye.jwt.util.ResourceUtils;

/**
 * JWT Token Build Utilities
 */
public class JwtBuildUtils {
    public static final String SIGN_KEY_LOCATION_PROPERTY = "smallrye.jwt.sign.key.location";
    public static final String SIGN_KEY_PROPERTY = "smallrye.jwt.sign.key";
    public static final String SIGN_KEY_ID_PROPERTY = "smallrye.jwt.sign.key.id";
    public static final String SIGN_KEY_RELAX_VALIDATION_PROPERTY = "smallrye.jwt.sign.relax-key-validation";
    public static final String ENC_KEY_LOCATION_PROPERTY = "smallrye.jwt.encrypt.key.location";
    public static final String ENC_KEY_PROPERTY = "smallrye.jwt.encrypt.key";
    public static final String ENC_KEY_ID_PROPERTY = "smallrye.jwt.encrypt.key.id";
    public static final String ENC_KEY_RELAX_VALIDATION_PROPERTY = "smallrye.jwt.encrypt.relax-key-validation";

    public static final String NEW_TOKEN_ISSUER_PROPERTY = "smallrye.jwt.new-token.issuer";
    public static final String NEW_TOKEN_AUDIENCE_PROPERTY = "smallrye.jwt.new-token.audience";
    public static final String NEW_TOKEN_OVERRIDE_CLAIMS_PROPERTY = "smallrye.jwt.new-token.override-matching-claims";
    public static final String NEW_TOKEN_ADD_DEFAULT_CLAIMS_PROPERTY = "smallrye.jwt.new-token.add-default-claims";
    public static final String NEW_TOKEN_LIFESPAN_PROPERTY = "smallrye.jwt.new-token.lifespan";
    public static final String NEW_TOKEN_SIGNATURE_ALG_PROPERTY = "smallrye.jwt.new-token.signature-algorithm";
    public static final String NEW_TOKEN_KEY_ENCRYPTION_ALG_PROPERTY = "smallrye.jwt.new-token.key-encryption-algorithm";
    public static final String NEW_TOKEN_CONTENT_ENCRYPTION_ALG_PROPERTY = "smallrye.jwt.new-token.content-encryption-algorithm";

    public static final String KEYSTORE_PASSWORD = "smallrye.jwt.keystore.password";
    public static final String KEYSTORE_TYPE = "smallrye.jwt.keystore.type";
    public static final String KEYSTORE_PROVIDER = "smallrye.jwt.keystore.provider";

    public static final String SIGN_KEYSTORE_KEY_ALIAS = "smallrye.jwt.keystore.sign.key.alias";
    public static final String SIGN_KEYSTORE_KEY_PASSWORD = "smallrye.jwt.keystore.sign.key.password";
    public static final String ENC_KEYSTORE_KEY_ALIAS = "smallrye.jwt.keystore.encrypt.key.alias";

    private JwtBuildUtils() {
        // no-op: utility class
    }

    static void setDefaultJwtClaims(JwtClaims claims, Long tokenLifespan) {

        Boolean addDefaultClaims = getConfigProperty(JwtBuildUtils.NEW_TOKEN_ADD_DEFAULT_CLAIMS_PROPERTY, Boolean.class,
                Boolean.TRUE);

        if (addDefaultClaims) {
            if (claims.getIssuedAt() == null) {
                claims.setIssuedAt(currentTimeInSecs());
            }
            setExpiryClaim(claims, tokenLifespan);

            if (claims.getJwtId() == null) {
                claims.setJwtId(UUID.randomUUID().toString());
            }
        }

        Boolean overrideMatchingClaims = getConfigProperty(NEW_TOKEN_OVERRIDE_CLAIMS_PROPERTY, Boolean.class);
        if (Boolean.TRUE.equals(overrideMatchingClaims) || claims.getIssuer() == null) {
            String issuer = getConfigProperty(NEW_TOKEN_ISSUER_PROPERTY, String.class);
            if (issuer != null) {
                claims.setIssuer(issuer);
            }
        }
        if (Boolean.TRUE.equals(overrideMatchingClaims) || claims.getAudience() == null) {
            String audience = getConfigProperty(NEW_TOKEN_AUDIENCE_PROPERTY, String.class);
            if (audience != null) {
                claims.setAudience(audience);
            }
        }
    }

    static <T> T getConfigProperty(String name, Class<T> cls) {
        return getConfigProperty(name, cls, null);
    }

    static <T> T getConfigProperty(String name, Class<T> cls, T defaultValue) {
        return getOptionalConfigProperty(name, cls).orElse(defaultValue);
    }

    static <T> Optional<T> getOptionalConfigProperty(String name, Class<T> cls) {
        return ConfigProvider.getConfig().getOptionalValue(name, cls);
    }

    static String readJsonContent(String jsonResName) {
        try {
            String content = ResourceUtils.readResource(jsonResName);
            if (content == null) {
                throw ImplMessages.msg.failureToOpenInputStreamFromJsonResName(jsonResName);
            }
            return content;
        } catch (IOException ex) {
            throw ImplMessages.msg.failureToReadJsonContentFromJsonResName(jsonResName, ex.getMessage(), ex);
        }
    }

    static void convertToClaims(JwtClaims claims, Map<String, Object> claimsMap) {
        claims.putAll(claimsMap);
    }

    /**
     * @return the current time in seconds since epoch
     */
    static int currentTimeInSecs() {
        return (int) (System.currentTimeMillis() / 1000);
    }

    private static void setExpiryClaim(JwtClaims claims, Long tokenLifespan) {
        if (claims.getExpirationTime() == null) {
            Long issuedAt = claims.getIssuedAt();
            if (issuedAt == null) {
                issuedAt = (long) currentTimeInSecs();
            }
            Long lifespan = tokenLifespan;
            if (lifespan == null) {
                lifespan = getConfigProperty(NEW_TOKEN_LIFESPAN_PROPERTY, Long.class, 300L);
            }

            claims.setExpirationTime(issuedAt + lifespan);
        }
    }

    static JwtClaims parseJwtClaims(String jwtLocation) {
        try {
            return JwtClaims.parse(readJsonContent(jwtLocation));
        } catch (Exception ex) {
            throw ImplMessages.msg.failureToParseJWTClaims(ex.getMessage(), ex);
        }
    }

    static JwtClaims parseJwtContent(String jwtContent) {
        try {
            return JwtClaims.parse(jwtContent);
        } catch (Exception ex) {
            throw ImplMessages.msg.failureToParseJWTClaims(ex.getMessage(), ex);
        }
    }

    static PrivateKey readPrivateKeyFromKeystore(String keyStorePath) {
        Optional<String> keyStorePassword = getOptionalConfigProperty(KEYSTORE_PASSWORD, String.class);
        if (keyStorePassword.isPresent()) {
            Optional<String> signKeyStoreKeyAlias = getOptionalConfigProperty(SIGN_KEYSTORE_KEY_ALIAS, String.class);
            if (signKeyStoreKeyAlias.isPresent()) {
                try {
                    KeyStore keyStore = KeyUtils.loadKeyStore(keyStorePath, keyStorePassword.get(),
                            getOptionalConfigProperty(KEYSTORE_TYPE, String.class),
                            getOptionalConfigProperty(KEYSTORE_PROVIDER, String.class));
                    return (PrivateKey) keyStore.getKey(signKeyStoreKeyAlias.get(),
                            getOptionalConfigProperty(SIGN_KEYSTORE_KEY_PASSWORD, String.class).orElse(keyStorePassword.get())
                                    .toCharArray());
                } catch (Exception ex) {
                    throw ImplMessages.msg.signingKeyCanNotBeReadFromKeystore(ex);
                }
            }
        }
        return null;
    }

    static PublicKey readPublicKeyFromKeystore(String keyStorePath) {
        Optional<String> keyStorePassword = getOptionalConfigProperty(KEYSTORE_PASSWORD, String.class);
        if (keyStorePassword.isPresent()) {
            Optional<String> encKeyStoreKeyAlias = getOptionalConfigProperty(ENC_KEYSTORE_KEY_ALIAS, String.class);
            if (encKeyStoreKeyAlias.isPresent()) {
                try {
                    KeyStore keyStore = KeyUtils.loadKeyStore(keyStorePath, keyStorePassword.get(),
                            getOptionalConfigProperty(KEYSTORE_TYPE, String.class),
                            getOptionalConfigProperty(KEYSTORE_PROVIDER, String.class));
                    return keyStore.getCertificate(encKeyStoreKeyAlias.get()).getPublicKey();
                } catch (Exception ex) {
                    throw ImplMessages.msg.encryptionKeyCanNotBeReadFromKeystore(ex);
                }
            }
        }
        return null;
    }

    /**
     * Compute X.509 certificate SHA-1 thumbprint (x5t) as Base64 URL-encoded string.
     */
    public static String computeThumbprint(X509Certificate cert) throws CertificateEncodingException {
        return computeThumbprint(cert, "SHA-1");
    }

    /**
     * Compute X.509 certificate SHA-256 thumbprint (x5t#S256) as Base64 URL-encoded string.
     */
    public static String computeThumbprintS256(X509Certificate cert) throws CertificateEncodingException {
        return computeThumbprint(cert, "SHA-256");
    }

    private static String computeThumbprint(X509Certificate cert, String algorithm) throws CertificateEncodingException {
        try {
            byte[] thumbprint = MessageDigest.getInstance(algorithm).digest(cert.getEncoded());
            return Base64.getUrlEncoder().withoutPadding().encodeToString(thumbprint);
        } catch (CertificateEncodingException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute " + algorithm + " certificate thumbprint", e);
        }
    }

    /**
     * Convert an EC public key to a Nimbus JWK.
     */
    public static JWK ecPublicKeyToJwk(ECPublicKey ecKey) {
        Curve curve = Curve.forECParameterSpec(ecKey.getParams());
        return new ECKey.Builder(curve, ecKey).build();
    }

    /**
     * Convert an EdDSA public key to a Nimbus JWK (OctetKeyPair).
     */
    public static JWK edEcPublicKeyToJwk(PublicKey key) {
        String alg = key.getAlgorithm();
        Curve curve;
        if ("Ed25519".equals(alg)) {
            curve = Curve.Ed25519;
        } else if ("Ed448".equals(alg)) {
            curve = Curve.Ed448;
        } else if ("EdDSA".equals(alg)) {
            // Detect curve from encoded key length: Ed25519=44, Ed448=69
            curve = key.getEncoded().length <= 50 ? Curve.Ed25519 : Curve.Ed448;
        } else {
            throw new IllegalArgumentException("Unsupported EdDSA algorithm: " + alg);
        }

        // The X.509 SubjectPublicKeyInfo for EdDSA wraps the raw public key in a
        // BIT STRING inside a SEQUENCE with an AlgorithmIdentifier.
        // The raw key bytes are after the ASN.1 header.
        // Rather than parsing ASN.1, use the key's encoded bytes and strip the header.
        byte[] encoded = key.getEncoded();
        // The last N bytes are the raw public key (32 for Ed25519, 57 for Ed448)
        int rawLen = curve == Curve.Ed25519 ? 32 : 57;
        if (encoded.length < rawLen) {
            throw new IllegalArgumentException("Encoded key too short");
        }
        byte[] rawBytes = new byte[rawLen];
        System.arraycopy(encoded, encoded.length - rawLen, rawBytes, 0, rawLen);

        return new OctetKeyPair.Builder(curve, Base64URL.encode(rawBytes)).build();
    }

    /**
     * Convert a public key to JWK by wrapping it in PEM format.
     * This is a fallback for keys that cannot be converted directly.
     */
    public static JWK pemFormatPublicKeyToJwk(PublicKey key) throws Exception {
        return JWK.parseFromPEMEncodedObjects(
                "-----BEGIN PUBLIC KEY-----\n"
                        + Base64.getEncoder().encodeToString(key.getEncoded())
                        + "\n-----END PUBLIC KEY-----");
    }
}
