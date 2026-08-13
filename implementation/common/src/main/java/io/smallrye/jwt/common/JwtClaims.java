package io.smallrye.jwt.common;

import java.io.StringReader;
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
    }

    public Object get(String name) {
        return claims.get(name);
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

    public void put(String name, Object value) {
        claims.put(name, value);
    }

    public boolean containsKey(String name) {
        return claims.containsKey(name);
    }

    public void remove(String name) {
        claims.remove(name);
    }

    public Set<String> keySet() {
        return claims.keySet();
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
        claims.put("aud", audiences);
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
        } else if (v instanceof Date) {
            return ((Date) v).getTime() / 1000;
        }
        return null;
    }

    public String toJsonString() {
        JsonObjectBuilder builder = JsonProviderHolder.jsonProvider().createObjectBuilder();
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            addToJsonBuilder(builder, entry.getKey(), entry.getValue());
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

    @SuppressWarnings("unchecked")
    private static void addToJsonBuilder(JsonObjectBuilder builder, String key, Object value) {
        if (value == null) {
            builder.addNull(key);
        } else if (value instanceof String) {
            builder.add(key, (String) value);
        } else if (value instanceof Long) {
            builder.add(key, (Long) value);
        } else if (value instanceof Integer) {
            builder.add(key, (Integer) value);
        } else if (value instanceof Double) {
            builder.add(key, (Double) value);
        } else if (value instanceof Boolean) {
            builder.add(key, (Boolean) value);
        } else if (value instanceof List) {
            JsonArrayBuilder arrayBuilder = JsonProviderHolder.jsonProvider().createArrayBuilder();
            for (Object item : (List<?>) value) {
                addToJsonArray(arrayBuilder, item);
            }
            builder.add(key, arrayBuilder);
        } else if (value instanceof Map) {
            JsonObjectBuilder nestedBuilder = JsonProviderHolder.jsonProvider().createObjectBuilder();
            for (Map.Entry<String, Object> entry : ((Map<String, Object>) value).entrySet()) {
                addToJsonBuilder(nestedBuilder, entry.getKey(), entry.getValue());
            }
            builder.add(key, nestedBuilder);
        } else {
            builder.add(key, value.toString());
        }
    }

    @SuppressWarnings("unchecked")
    private static void addToJsonArray(JsonArrayBuilder arrayBuilder, Object value) {
        if (value == null) {
            arrayBuilder.addNull();
        } else if (value instanceof String) {
            arrayBuilder.add((String) value);
        } else if (value instanceof Long) {
            arrayBuilder.add((Long) value);
        } else if (value instanceof Integer) {
            arrayBuilder.add((Integer) value);
        } else if (value instanceof Double) {
            arrayBuilder.add((Double) value);
        } else if (value instanceof Boolean) {
            arrayBuilder.add((Boolean) value);
        } else if (value instanceof Map) {
            JsonObjectBuilder nestedBuilder = JsonProviderHolder.jsonProvider().createObjectBuilder();
            for (Map.Entry<String, Object> entry : ((Map<String, Object>) value).entrySet()) {
                addToJsonBuilder(nestedBuilder, entry.getKey(), entry.getValue());
            }
            arrayBuilder.add(nestedBuilder);
        } else {
            arrayBuilder.add(value.toString());
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
