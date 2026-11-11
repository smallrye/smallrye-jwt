package io.smallrye.jwk;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.jboss.logging.Logger;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.JSONObjectUtils;

/**
 * A set of JSON Web Keys.
 */
public class JsonWebKeySet {

    private static final Logger LOG = Logger.getLogger(JsonWebKeySet.class);

    private final List<JsonWebKey> keys;

    private JsonWebKeySet(List<JsonWebKey> keys) {
        this.keys = Collections.unmodifiableList(keys);
    }

    /**
     * Parse a JSON Web Key Set.
     * <p>
     * The keys which can not be parsed, for example, the keys of an unsupported type or the keys with
     * an invalid or inconsistent property, are logged and skipped, the remaining keys are returned.
     *
     * @param content the JSON Web Key Set content
     * @return the JSON Web Key Set
     * @throws JsonWebKeyException if the content is not a JSON Web Key Set
     */
    @SuppressWarnings("unchecked")
    public static JsonWebKeySet parse(String content) throws JsonWebKeyException {
        List<Object> keyArray;
        try {
            keyArray = JSONObjectUtils.getJSONArray(JSONObjectUtils.parse(content), "keys");
        } catch (ParseException ex) {
            throw new JsonWebKeyException("Invalid JSON Web Key Set: " + ex.getMessage(), ex);
        }
        if (keyArray == null) {
            throw new JsonWebKeyException("Invalid JSON Web Key Set: missing required \"keys\" member");
        }

        List<JsonWebKey> keys = new ArrayList<>(keyArray.size());
        for (Object keyObject : keyArray) {
            if (!(keyObject instanceof Map)) {
                throw new JsonWebKeyException("Invalid JSON Web Key Set: the \"keys\" array must contain JSON objects only");
            }
            Map<String, Object> keyJson = (Map<String, Object>) keyObject;
            try {
                keys.add(JsonWebKey.of(JWK.parse(keyJson)));
            } catch (Exception ex) {
                // an invalid key does not invalidate the whole set, as in jose4j
                LOG.warnf("Ignoring the JSON Web Key with the key id '%s' which can not be parsed: %s",
                        keyJson.get("kid"), ex.getMessage());
            }
        }
        return new JsonWebKeySet(keys);
    }

    /**
     * Create a JSON Web Key Set containing the given keys.
     *
     * @param keys the keys
     * @return the JSON Web Key Set
     */
    public static JsonWebKeySet of(JsonWebKey... keys) {
        return new JsonWebKeySet(Arrays.asList(keys));
    }

    /**
     * The keys of this set.
     *
     * @return an unmodifiable list of the keys
     */
    public List<JsonWebKey> keys() {
        return keys;
    }

    /**
     * The JSON Web Key Set as a JSON string.
     * <p>
     * Each key is output as by {@link JsonWebKey#asJsonString()}: the private key material of the asymmetric keys
     * is omitted, the `k` secret values of the symmetric keys are included.
     * Use {@link #asJsonString(JsonWebKey.OutputLevel)} with {@link JsonWebKey.OutputLevel#PUBLIC_ONLY}
     * to get a representation which can be published, for example, at a JSON Web Key Set endpoint.
     *
     * @return the JSON representation of this JSON Web Key Set
     */
    public String asJsonString() {
        List<Map<String, Object>> jwks = new ArrayList<>(keys.size());
        for (JsonWebKey key : keys) {
            jwks.add(key.asMap());
        }
        return toJsonString(jwks);
    }

    /**
     * The JSON Web Key Set as a JSON string.
     *
     * @param outputLevel controls whether the private or secret key material of every key is included
     * @return the JSON representation of this JSON Web Key Set
     */
    public String asJsonString(JsonWebKey.OutputLevel outputLevel) {
        List<Map<String, Object>> jwks = new ArrayList<>(keys.size());
        for (JsonWebKey key : keys) {
            jwks.add(key.asMap(outputLevel));
        }
        return toJsonString(jwks);
    }

    private static String toJsonString(List<Map<String, Object>> jwks) {
        Map<String, Object> jwkSet = new LinkedHashMap<>();
        jwkSet.put("keys", jwks);
        return JSONObjectUtils.toJSONString(jwkSet);
    }

    /**
     * The key with the given `kid` key identifier.
     *
     * @param kid the key identifier
     * @return the key, or null if this set has no key with this identifier
     */
    public JsonWebKey keyWithId(String kid) {
        if (kid != null) {
            for (JsonWebKey key : keys) {
                if (kid.equals(key.keyId())) {
                    return key;
                }
            }
        }
        return null;
    }
}
