package io.smallrye.jwt.build.impl;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.json.JsonNumber;
import javax.json.JsonString;
import javax.json.JsonValue;

import org.eclipse.microprofile.jwt.Claims;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;

import io.smallrye.jwt.build.JwtClaimsBuilder;
import io.smallrye.jwt.build.JwtHeadersBuilder;

/**
 * Default JWT Claims Builder
 *
 */
class JwtBuilderImpl extends JwtSignerImpl implements JwtClaimsBuilder, JwtHeadersBuilder {

    JwtBuilderImpl() {

    }

    JwtBuilderImpl(String jsonLocation) {
        super(parseJsonToClaims(jsonLocation));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsBuilder claim(String name, Object value) {
        claims.setClaim(name, prepareValue(value));
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsBuilder issuer(String issuer) {
        claims.setIssuer(issuer);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsBuilder audience(String audience) {
        return audience(Collections.singleton(audience));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsBuilder audience(Set<String> audiences) {
        claims.setAudience(audiences.stream().collect(Collectors.toList()));
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsBuilder subject(String subject) {
        claims.setSubject(subject);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsBuilder upn(String upn) {
        claims.setClaim(Claims.upn.name(), upn);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsBuilder preferredUserName(String preferredUserName) {
        claims.setClaim(Claims.preferred_username.name(), preferredUserName);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsBuilder issuedAt(long issuedAt) {
        claims.setIssuedAt(NumericDate.fromSeconds(issuedAt));
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsBuilder expiresAt(long expiredAt) {
        claims.setExpirationTime(NumericDate.fromSeconds(expiredAt));
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsBuilder groups(String group) {
        return groups(Collections.singleton(group));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsBuilder groups(Set<String> groups) {
        claims.setClaim("groups", groups.stream().collect(Collectors.toList()));
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtHeadersBuilder headers() {
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtHeadersBuilder header(String name, Object value) {
        headers.put(name, value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtHeadersBuilder keyId(String keyId) {
        headers.put("kid", keyId);
        return this;
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    private Object prepareValue(Object value) {
        if (value instanceof Collection) {
            return ((Collection) value).stream().map(o -> prepareValue(o)).collect(Collectors.toList());
        }

        if (value instanceof Map) {
            Map<String, Object> map = (Map) value;
            Map<String, Object> newMap = new LinkedHashMap<>();
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                newMap.put(entry.getKey(), prepareValue(entry.getValue()));
            }
            return newMap;
        }

        if (value instanceof JsonValue) {
            return convertJsonValue((JsonValue) value);
        }

        if (value instanceof Number || value instanceof Boolean) {
            return value;
        }

        return value.toString();
    }

    private static Object convertJsonValue(JsonValue jsonValue) {
        if (jsonValue instanceof JsonString) {
            String jsonString = jsonValue.toString();
            return jsonString.toString().substring(1, jsonString.length() - 1);
        } else if (jsonValue instanceof JsonNumber) {
            JsonNumber jsonNumber = (JsonNumber) jsonValue;
            if (jsonNumber.isIntegral()) {
                return jsonNumber.longValue();
            } else {
                return jsonNumber.doubleValue();
            }
        } else if (jsonValue == JsonValue.TRUE) {
            return true;
        } else if (jsonValue == JsonValue.FALSE) {
            return false;
        } else {
            return null;
        }
    }

    private static JwtClaims parseJsonToClaims(String jsonLocation) {
        return JwtSigningUtils.parseJwtClaims(jsonLocation);
    }
}