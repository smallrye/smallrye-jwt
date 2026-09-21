package io.smallrye.jwk;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
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
            keys.add(JsonWebKey.of(jwk));
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
     * Only the public keys are included: the private key material is dropped and the symmetric keys,
     * which have no public form, are skipped. This representation can be published,
     * for example, at a JSON Web Key Set endpoint.
     *
     * @return the JSON representation of this JSON Web Key Set
     */
    public String asJsonString() {
        List<JWK> jwks = new ArrayList<>(keys.size());
        for (JsonWebKey key : keys) {
            jwks.add(key.jwk());
        }
        return new JWKSet(jwks).toString();
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
