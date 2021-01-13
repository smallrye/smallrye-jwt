package io.smallrye.jwt.build.impl;

import java.io.IOException;
import java.util.Map;
import java.util.UUID;

import org.eclipse.microprofile.config.ConfigProvider;
import org.eclipse.microprofile.jwt.Claims;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;

import io.smallrye.jwt.util.ResourceUtils;

/**
 * JWT Token Build Utilities
 */
public class JwtBuildUtils {

    private JwtBuildUtils() {
        // no-op: utility class
    }

    static void setDefaultJwtClaims(JwtClaims claims, Long tokenLifespan) {

        if (!claims.hasClaim(Claims.iat.name())) {
            claims.setIssuedAt(NumericDate.fromSeconds(currentTimeInSecs()));
        }
        setExpiryClaim(claims, tokenLifespan);
        if (!claims.hasClaim(Claims.jti.name())) {
            claims.setClaim(Claims.jti.name(), UUID.randomUUID().toString());
        }
        if (!claims.hasClaim(Claims.iss.name())) {
            String issuer = getConfigProperty("smallrye.jwt.new-token.issuer", String.class);
            if (issuer != null) {
                claims.setIssuer(issuer);
            }
        }
        if (!claims.hasClaim(Claims.aud.name())) {
            String audience = getConfigProperty("smallrye.jwt.new-token.audience", String.class);
            if (audience != null) {
                claims.setAudience(audience);
            }
        }
    }

    static <T> T getConfigProperty(String name, Class<T> cls) {
        return getConfigProperty(name, cls, null);
    }

    static <T> T getConfigProperty(String name, Class<T> cls, T defaultValue) {
        return ConfigProvider.getConfig().getOptionalValue(name, cls).orElse(defaultValue);
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
                lifespan = getConfigProperty("smallrye.jwt.new-token.lifespan", Long.class, 300L);
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
}
