package io.smallrye.jwk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import io.smallrye.jwk.JsonWebKey.OutputLevel;

public class JsonWebKeyTest {

    private static final String SECRET_JWK = "{\"kty\":\"oct\",\"kid\":\"2\",\"k\":\"AAECAwQFBgcICQoLDA0ODw\"}";

    @Test
    public void asymmetricKeyOmitsPrivateMaterialByDefault() throws Exception {
        RsaJsonWebKey key = RsaJsonWebKey.builder(2048).keyId("1").build();

        assertTrue(key.asMap().containsKey("n"));
        assertFalse(key.asMap().containsKey("d"));
        assertEquals("1", key.asMap().get("kid"));
        assertFalse(key.asJsonString().contains("\"d\""));

        assertTrue(key.asMap(OutputLevel.INCLUDE_PRIVATE).containsKey("d"));
        assertTrue(key.asJsonString(OutputLevel.INCLUDE_PRIVATE).contains("\"d\""));
        assertFalse(key.asMap(OutputLevel.PUBLIC_ONLY).containsKey("d"));
    }

    @Test
    public void secretKeyIncludesSecretByDefault() throws Exception {
        JsonWebKey key = JsonWebKey.parse(SECRET_JWK);

        assertTrue(key.asMap().containsKey("k"));
        assertTrue(key.asJsonString().contains("\"k\""));

        assertFalse(key.asMap(OutputLevel.PUBLIC_ONLY).containsKey("k"));
        assertEquals("2", key.asMap(OutputLevel.PUBLIC_ONLY).get("kid"));
        assertEquals("oct", key.asMap(OutputLevel.PUBLIC_ONLY).get("kty"));
        assertFalse(key.asJsonString(OutputLevel.PUBLIC_ONLY).contains("\"k\""));
    }

    @Test
    public void keySetSkipsInvalidKeys() throws Exception {
        String rsaJwk = RsaJsonWebKey.builder(2048).keyId("1").build().asJsonString();
        String json = "{\"keys\":[" + rsaJwk
                + ",{\"kty\":\"RSA\",\"kid\":\"no-modulus\",\"e\":\"AQAB\"}"
                + ",{\"kty\":\"EC\",\"kid\":\"not-on-curve\",\"crv\":\"P-256\",\"x\":\"AQAB\",\"y\":\"AQAB\"}"
                + ",{\"kty\":\"RSA\",\"kid\":\"bad-ops\",\"n\":\"AQAB\",\"e\":\"AQAB\",\"key_ops\":[\"fly\"]}"
                + ",{\"kty\":\"FOO\",\"kid\":\"unknown-type\"}"
                + "," + SECRET_JWK + "]}";

        JsonWebKeySet keySet = JsonWebKeySet.parse(json);
        assertEquals(2, keySet.keys().size());
        assertEquals("1", keySet.keys().get(0).keyId());
        assertEquals("2", keySet.keys().get(1).keyId());
    }

    @Test
    public void keySetRequiresKeysArray() {
        assertThrows(JsonWebKeyException.class, () -> JsonWebKeySet.parse("{\"kty\":\"RSA\"}"));
        assertThrows(JsonWebKeyException.class, () -> JsonWebKeySet.parse("{\"keys\":[\"not-an-object\"]}"));
        assertThrows(JsonWebKeyException.class, () -> JsonWebKeySet.parse("not json"));
    }

    @Test
    public void keySetOutputLevels() throws Exception {
        JsonWebKeySet keySet = JsonWebKeySet.of(RsaJsonWebKey.builder(2048).keyId("1").build(),
                JsonWebKey.parse(SECRET_JWK));

        String json = keySet.asJsonString();
        assertFalse(json.contains("\"d\""));
        assertTrue(json.contains("\"k\""));
        assertEquals(2, JsonWebKeySet.parse(json).keys().size());

        json = keySet.asJsonString(OutputLevel.PUBLIC_ONLY);
        assertFalse(json.contains("\"d\""));
        assertFalse(json.contains("\"k\""));
        assertTrue(json.contains("\"kid\":\"2\""));

        json = keySet.asJsonString(OutputLevel.INCLUDE_PRIVATE);
        assertTrue(json.contains("\"d\""));
        assertTrue(json.contains("\"k\""));
        assertEquals(2, JsonWebKeySet.parse(json).keys().size());
    }
}
