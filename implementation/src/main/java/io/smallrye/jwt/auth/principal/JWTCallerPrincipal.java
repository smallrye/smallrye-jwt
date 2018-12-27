package io.smallrye.jwt.auth.principal;


import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;
import javax.security.auth.Subject;

import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;

/**
 * An abstract CallerPrincipal implementation that provides access to the JWT claims that are required by
 * the microprofile token.
 */
public abstract class JWTCallerPrincipal implements JsonWebToken {
    private static final String TMP = "tmp";
    
    private String rawToken;
    private String tokenType;
    
    /**
     * Create a JWTCallerPrincipal with the caller's name
     *
     * @param name - caller's name
     */
    public JWTCallerPrincipal(String rawToken, String tokenType) {
        this.rawToken = rawToken;
        this.tokenType = tokenType;
    }

    @Override
    public String getName() {
        String principalName = getClaim(Claims.upn.name());
        if (principalName == null) {
            principalName = getClaim(Claims.preferred_username.name());
            if (principalName == null) {
                principalName = getClaim(Claims.sub.name());
            }
        }
        return principalName;
    }
    
    @Override
    public Set<String> getClaimNames() {
        Set<String> names = new HashSet<>(doGetClaimNames());
        names.add(Claims.raw_token.name());
        return names;
    }
    
    protected abstract Collection<String> doGetClaimNames();

    @Override
    public <T> T getClaim(String claimName) {
        @SuppressWarnings("unchecked")
        T claimValue = Claims.raw_token.name().equals(claimName) ? (T)rawToken : (T)getClaimValue(claimName);
        return claimValue;
    }

    protected abstract Object getClaimValue(String claimName);

    @Override
    public boolean implies(Subject subject) {
        return false;
    }
    
    public String toString() {
        return toString(false);
    }

    /**
     * TODO: showAll is ignored and currently assumed true
     *
     * @param showAll - should all claims associated with the JWT be displayed or should only those defined in the
     *                JsonWebToken interface be displayed.
     * @return JWTCallerPrincipal string view
     */
    public String toString(boolean showAll) {
        String toString = "DefaultJWTCallerPrincipal{" +
                "id='" + getTokenID() + '\'' +
                ", name='" + getName() + '\'' +
                ", expiration=" + getExpirationTime() +
                ", notBefore=" + getClaim(Claims.nbf.name()) +
                ", issuedAt=" + getIssuedAtTime() +
                ", issuer='" + getIssuer() + '\'' +
                ", audience=" + getAudience() +
                ", subject='" + getSubject() + '\'' +
                ", type='" + tokenType + '\'' +
                ", issuedFor='" + getClaim("azp") + '\'' +
                ", authTime=" + getClaim("auth_time") +
                ", givenName='" + getClaim("given_name") + '\'' +
                ", familyName='" + getClaim("family_name") + '\'' +
                ", middleName='" + getClaim("middle_name") + '\'' +
                ", nickName='" + getClaim("nickname") + '\'' +
                ", preferredUsername='" + getClaim("preferred_username") + '\'' +
                ", email='" + getClaim("email") + '\'' +
                ", emailVerified=" + getClaim(Claims.email_verified.name()) +
                ", allowedOrigins=" + getClaim("allowedOrigins") +
                ", updatedAt=" + getClaim("updated_at") +
                ", acr='" + getClaim("acr") + '\'';
        StringBuilder tmp = new StringBuilder(toString);
        tmp.append(", groups=[");
        for (String group : getGroups()) {
            tmp.append(group);
            tmp.append(',');
        }
        tmp.setLength(tmp.length() - 1);
        tmp.append("]}");
        return tmp.toString();
    }
    
    protected static JsonObject replaceMap(Map<String, Object> map) {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            Object entryValue = entry.getValue();
            if (entryValue instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> mapValue = (Map<String, Object>) entryValue;
                JsonObject entryJsonObject = replaceMap(mapValue);
                builder.add(entry.getKey(), entryJsonObject);
            } else if (entryValue instanceof List) {
                JsonArray array = (JsonArray) wrapValue(entryValue);
                builder.add(entry.getKey(), array);
            } else if (entryValue instanceof Long || entryValue instanceof Integer) {
                long lvalue = ((Number) entryValue).longValue();
                builder.add(entry.getKey(), lvalue);
            } else if (entryValue instanceof Double || entryValue instanceof Float) {
                double dvalue = ((Number) entryValue).doubleValue();
                builder.add(entry.getKey(), dvalue);
            } else if (entryValue instanceof Boolean) {
                boolean flag = ((Boolean) entryValue).booleanValue();
                builder.add(entry.getKey(), flag);
            } else if (entryValue instanceof String) {
                builder.add(entry.getKey(), entryValue.toString());
            }
        }
        return builder.build();
    }

    protected static JsonValue wrapValue(Object value) {
        JsonValue jsonValue = null;
        if (value instanceof Number) {
            Number number = (Number) value;
            if ((number instanceof Long) || (number instanceof Integer)) {
                jsonValue = Json.createObjectBuilder()
                        .add(TMP, number.longValue())
                        .build()
                        .getJsonNumber(TMP);
            } else {
                jsonValue = Json.createObjectBuilder()
                        .add(TMP, number.doubleValue())
                        .build()
                        .getJsonNumber(TMP);
            }
        } else if (value instanceof Boolean) {
            Boolean flag = (Boolean) value;
            jsonValue = flag ? JsonValue.TRUE : JsonValue.FALSE;
        } else if (value instanceof List) {
            JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
            @SuppressWarnings("unchecked")
            List<Object> list = (List<Object>) value;
            for (Object element : list) {
                if (element instanceof String) {
                    arrayBuilder.add(element.toString());
                } else {
                    JsonValue jvalue = wrapValue(element);
                    arrayBuilder.add(jvalue);
                }
            }
            jsonValue = arrayBuilder.build();
        }
        return jsonValue;
    }
}
