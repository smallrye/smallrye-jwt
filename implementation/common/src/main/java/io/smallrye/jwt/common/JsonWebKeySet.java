package io.smallrye.jwt.common;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

/**
 * A set of JSON Web Keys.
 */
public class JsonWebKeySet {

    private final List<JsonWebKey> keys;

    private JsonWebKeySet(List<JsonWebKey> keys) {
        this.keys = Collections.unmodifiableList(keys);
    }

    /**
     * Parse a JSON Web Key Set.
     *
     * @param content the JSON Web Key Set content
     * @return the JSON Web Key Set
     * @throws JsonWebKeyException if the content is not a valid JSON Web Key Set
     */
    public static JsonWebKeySet parse(String content) throws JsonWebKeyException {
        List<JWK> jwks;
        try {
            jwks = JWKSet.parse(content).getKeys();
        } catch (ParseException ex) {
            throw new JsonWebKeyException("Invalid JSON Web Key Set: " + ex.getMessage(), ex);
        }

        List<JsonWebKey> keys = new ArrayList<>(jwks.size());
        for (JWK jwk : jwks) {
            keys.add(new JsonWebKey(jwk));
        }
        return new JsonWebKeySet(keys);
    }

    /**
     * Create a JSON Web Key Set containing a single key.
     *
     * @param key the key
     * @return the JSON Web Key Set
     */
    public static JsonWebKeySet of(JsonWebKey key) {
        return new JsonWebKeySet(Collections.singletonList(key));
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
