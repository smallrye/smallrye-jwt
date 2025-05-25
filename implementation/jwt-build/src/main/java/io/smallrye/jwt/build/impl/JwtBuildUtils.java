package io.smallrye.jwt.build.impl;

import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.eclipse.microprofile.config.ConfigProvider;
import org.eclipse.microprofile.jwt.Claims;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;

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
            if (!claims.hasClaim(Claims.iat.name())) {
                claims.setIssuedAt(NumericDate.fromSeconds(currentTimeInSecs()));
            }
            setExpiryClaim(claims, tokenLifespan);

            if (!claims.hasClaim(Claims.jti.name())) {
                claims.setClaim(Claims.jti.name(), UUID.randomUUID().toString());
            }
        }

        Boolean overrideMatchingClaims = getConfigProperty(NEW_TOKEN_OVERRIDE_CLAIMS_PROPERTY, Boolean.class);
        if (Boolean.TRUE.equals(overrideMatchingClaims) || !claims.hasClaim(Claims.iss.name())) {
            String issuer = getConfigProperty(NEW_TOKEN_ISSUER_PROPERTY, String.class);
            if (issuer != null) {
                claims.setIssuer(issuer);
            }
        }
        if (Boolean.TRUE.equals(overrideMatchingClaims) || !claims.hasClaim(Claims.aud.name())) {
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

    static JwtClaims convertToClaims(Map<String, Object> claimsMap) {
        JwtClaims claims = new JwtClaims();
        convertToClaims(claims, claimsMap);
        return claims;
    }

    static void convertToClaims(JwtClaims claims, Map<String, Object> claimsMap) {
        for (Map.Entry<String, Object> entry : claimsMap.entrySet()) {
            claims.setClaim(entry.getKey(), entry.getValue());
        }
    }

    /**
     * @return the current time in seconds since epoch
     */
    static int currentTimeInSecs() {
        return (int) (System.currentTimeMillis() / 1000);
    }

    private static void setExpiryClaim(JwtClaims claims, Long tokenLifespan) {
        if (!claims.hasClaim(Claims.exp.name())) {
            Object value = claims.getClaimValue(Claims.iat.name());
            Long issuedAt = (value instanceof NumericDate) ? ((NumericDate) value).getValue() : (Long) value;
            Long lifespan = tokenLifespan;
            if (lifespan == null) {
                lifespan = getConfigProperty(NEW_TOKEN_LIFESPAN_PROPERTY, Long.class, 300L);
            }

            claims.setExpirationTime(NumericDate.fromSeconds(issuedAt + lifespan));
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
}
