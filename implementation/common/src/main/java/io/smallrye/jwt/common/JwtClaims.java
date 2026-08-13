package io.smallrye.jwt.common;

import java.io.StringReader;
import java.math.BigDecimal;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonNumber;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonReader;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;
import jakarta.json.spi.JsonProvider;

/**
 * A mutable container for JWT claims backed by a Map.
 */
public class JwtClaims {

    private final Map<String, Object> claims;

    public JwtClaims() {
        this.claims = new LinkedHashMap<>();
    }

    public JwtClaims(Map<String, Object> claims) {
        this.claims = new LinkedHashMap<>(claims);
        // Nimbus JWTClaimsSet.getClaims() returns 'exp', 'iat' and 'nbf' as Date, normalize them to epoch seconds
        for (Map.Entry<String, Object> entry : this.claims.entrySet()) {
            if (entry.getValue() instanceof Date) {
                entry.setValue(((Date) entry.getValue()).getTime() / 1000);
            }
        }
    }

    public Object getClaim(String name) {
        return claims.get(name);
    }

    public void setClaim(String name, Object value) {
        claims.put(name, value);
    }

    public boolean hasClaim(String name) {
        return claims.containsKey(name);
    }

    public void remove(String name) {
        claims.remove(name);
    }

    public Set<String> getClaimNames() {
        return Collections.unmodifiableSet(claims.keySet());
    }

    public void putAll(Map<String, Object> other) {
        claims.putAll(other);
    }

    public Map<String, Object> asMap() {
        return claims;
    }

    // Standard claim accessors

    public String getIssuer() {
        Object v = claims.get("iss");
        return v != null ? v.toString() : null;
    }

    public void setIssuer(String issuer) {
        claims.put("iss", issuer);
    }

    public String getSubject() {
        Object v = claims.get("sub");
        return v != null ? v.toString() : null;
    }

    public void setSubject(String subject) {
        claims.put("sub", subject);
    }

    @SuppressWarnings("unchecked")
    public List<String> getAudience() {
        Object v = claims.get("aud");
        if (v instanceof List) {
            return (List<String>) v;
        } else if (v instanceof String) {
            return Collections.singletonList((String) v);
        }
        return null;
    }

    public void setAudience(String audience) {
        claims.put("aud", audience);
    }

    public void setAudience(List<String> audiences) {
        if (audiences.size() == 1) {
            // a single audience is set as a string, as jose4j did
            setAudience(audiences.get(0));
        } else {
            claims.put("aud", audiences);
        }
    }

    public Long getIssuedAt() {
        return getNumericDate("iat");
    }

    public void setIssuedAt(long issuedAt) {
        claims.put("iat", issuedAt);
    }

    public Long getExpirationTime() {
        return getNumericDate("exp");
    }

    public void setExpirationTime(long exp) {
        claims.put("exp", exp);
    }

    public Long getNotBefore() {
        return getNumericDate("nbf");
    }

    public String getJwtId() {
        Object v = claims.get("jti");
        return v != null ? v.toString() : null;
    }

    public void setJwtId(String jti) {
        claims.put("jti", jti);
    }

    @SuppressWarnings("unchecked")
    public List<String> getGroups() {
        Object v = claims.get("groups");
        if (v instanceof List) {
            return (List<String>) v;
        }
        return null;
    }

    public void setGroups(List<String> groups) {
        claims.put("groups", groups);
    }

    public String getUpn() {
        Object v = claims.get("upn");
        return v != null ? v.toString() : null;
    }

    public String getPreferredUsername() {
        Object v = claims.get("preferred_username");
        return v != null ? v.toString() : null;
    }

    private Long getNumericDate(String name) {
        Object v = claims.get(name);
        if (v instanceof Number) {
            return ((Number) v).longValue();
        }
        return null;
    }

    public String toJsonString() {
        JsonObjectBuilder builder = JsonProviderHolder.jsonProvider().createObjectBuilder();
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            builder.add(entry.getKey(), toJsonValue(entry.getValue()));
        }
        return builder.build().toString();
    }

    public static JwtClaims parse(String json) {
        try (JsonReader reader = JsonProviderHolder.jsonProvider().createReader(new StringReader(json))) {
            JsonObject jsonObject = reader.readObject();
            Map<String, Object> map = new LinkedHashMap<>();
            for (Map.Entry<String, JsonValue> entry : jsonObject.entrySet()) {
                map.put(entry.getKey(), convertJsonValue(entry.getValue()));
            }
            return new JwtClaims(map);
        }
    }

    // Converts a claim value to JSON recursively, in one place for the object and array values, as jose4j did
    @SuppressWarnings("unchecked")
    private static JsonValue toJsonValue(Object value) {
        JsonProvider provider = JsonProviderHolder.jsonProvider();
        if (value == null) {
            return JsonValue.NULL;
        } else if (value instanceof String) {
            return provider.createValue((String) value);
        } else if (value instanceof Long || value instanceof Integer) {
            return provider.createValue(((Number) value).longValue());
        } else if (value instanceof Double) {
            return provider.createValue((Double) value);
        } else if (value instanceof Number) {
            // Float, BigInteger, BigDecimal, etc, written as JSON numbers, as jose4j did
            return provider.createValue(new BigDecimal(value.toString()));
        } else if (value instanceof Boolean) {
            return (Boolean) value ? JsonValue.TRUE : JsonValue.FALSE;
        } else if (value instanceof List) {
            // arrays, including the nested ones, as jose4j did
            JsonArrayBuilder arrayBuilder = provider.createArrayBuilder();
            for (Object item : (List<?>) value) {
                arrayBuilder.add(toJsonValue(item));
            }
            return arrayBuilder.build();
        } else if (value instanceof Map) {
            JsonObjectBuilder objectBuilder = provider.createObjectBuilder();
            for (Map.Entry<String, Object> entry : ((Map<String, Object>) value).entrySet()) {
                objectBuilder.add(entry.getKey(), toJsonValue(entry.getValue()));
            }
            return objectBuilder.build();
        } else {
            return provider.createValue(value.toString());
        }
    }

    private static Object convertJsonValue(JsonValue jsonValue) {
        switch (jsonValue.getValueType()) {
            case STRING:
                return ((JsonString) jsonValue).getString();
            case NUMBER:
                JsonNumber num = (JsonNumber) jsonValue;
                if (num.isIntegral()) {
                    return num.longValue();
                }
                return num.doubleValue();
            case TRUE:
                return Boolean.TRUE;
            case FALSE:
                return Boolean.FALSE;
            case NULL:
                return null;
            case ARRAY:
                return jsonValue.asJsonArray().stream()
                        .map(JwtClaims::convertJsonValue)
                        .collect(Collectors.toList());
            case OBJECT:
                Map<String, Object> nested = new LinkedHashMap<>();
                for (Map.Entry<String, JsonValue> e : jsonValue.asJsonObject().entrySet()) {
                    nested.put(e.getKey(), convertJsonValue(e.getValue()));
                }
                return nested;
            default:
                return jsonValue.toString();
        }
    }
}
