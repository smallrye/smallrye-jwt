package io.smallrye.jwk;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.junit.Test;

import io.smallrye.jwk.JsonWebKey.OutputLevel;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.util.KeyUtils;

public class JsonWebKeyTest {

    private static final String SECRET_JWK = "{\"kty\":\"oct\",\"kid\":\"2\",\"k\":\"AAECAwQFBgcICQoLDA0ODw\"}";

    // RFC 7638, section 3.1
    private static final String RFC_7638_JWK = "{\"kty\":\"RSA\",\"kid\":\"2011-04-29\",\"e\":\"AQAB\",\"n\":\""
            + "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWK"
            + "RXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMic"
            + "AtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3"
            + "XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
            + "\"}";

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

    @Test
    public void rfc7638Thumbprint() throws Exception {
        JsonWebKey key = JsonWebKey.parse(RFC_7638_JWK);
        assertEquals("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", key.computeThumbprint());
    }

    @Test
    public void rsaKeyRoundTrip() throws Exception {
        RSAPublicKey publicKey = (RSAPublicKey) KeyUtils.generateKeyPair(2048).getPublic();

        RsaJsonWebKey key = RsaJsonWebKey.builder(publicKey).keyId("rsa-1").keyUse("sig").algorithm("RS256").build();
        assertEquals("RSA", key.keyType());
        assertEquals("rsa-1", key.keyId());
        assertEquals("sig", key.keyUse());
        assertEquals("RS256", key.algorithm());
        assertEquals(publicKey, key.publicKey());

        JsonWebKey parsed = JsonWebKey.parse(key.asJsonString());
        assertTrue(parsed instanceof RsaJsonWebKey);
        assertEquals("rsa-1", parsed.keyId());
        assertEquals(publicKey, ((RsaJsonWebKey) parsed).publicKey());

        assertEquals(publicKey, JsonWebKey.jwk(publicKey).publicKey());
    }

    @Test
    public void ecKeyRoundTrip() throws Exception {
        ECPublicKey publicKey = (ECPublicKey) KeyUtils.generateKeyPair(256, SignatureAlgorithm.ES256).getPublic();

        EcJsonWebKey key = EcJsonWebKey.builder(publicKey).keyId("ec-1").build();
        assertEquals("EC", key.keyType());
        assertEquals("P-256", key.curve());
        assertEquals(publicKey, key.publicKey());

        JsonWebKey parsed = JsonWebKey.parse(key.asJsonString());
        assertTrue(parsed instanceof EcJsonWebKey);
        assertEquals("ec-1", parsed.keyId());
        assertEquals(publicKey, ((EcJsonWebKey) parsed).publicKey());

        assertEquals(publicKey, JsonWebKey.jwk(publicKey).publicKey());
    }

    @Test
    public void octetKeyPairRoundTrip() throws Exception {
        KeyPair edKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();

        OctetKeyPairJsonWebKey key = OctetKeyPairJsonWebKey.builder(edKeyPair.getPublic()).keyId("ed-1").build();
        assertEquals("OKP", key.keyType());
        assertEquals("Ed25519", key.curve());
        assertEquals(edKeyPair.getPublic(), key.publicKey());

        JsonWebKey parsed = JsonWebKey.parse(key.asJsonString());
        assertTrue(parsed instanceof OctetKeyPairJsonWebKey);
        assertEquals("ed-1", parsed.keyId());
        assertEquals(edKeyPair.getPublic(), ((OctetKeyPairJsonWebKey) parsed).publicKey());

        KeyPair xKeyPair = KeyPairGenerator.getInstance("X25519").generateKeyPair();
        AsymmetricJsonWebKey xKey = JsonWebKey.jwk(xKeyPair.getPublic());
        assertEquals("X25519", ((OctetKeyPairJsonWebKey) xKey).curve());
        assertEquals(xKeyPair.getPublic(), ((OctetKeyPairJsonWebKey) JsonWebKey.parse(xKey.asJsonString())).publicKey());
    }

    @Test
    public void secretKeyRoundTrip() throws Exception {
        JsonWebKey key = JsonWebKey.parse(SECRET_JWK);
        assertTrue(key instanceof SecretJsonWebKey);
        assertEquals("oct", key.keyType());
        assertArrayEquals(new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
                ((SecretJsonWebKey) key).secretKey().getEncoded());
    }

    @Test
    public void keySetKeyWithId() throws Exception {
        JsonWebKeySet keySet = JsonWebKeySet.of(RsaJsonWebKey.builder(2048).keyId("1").build(),
                JsonWebKey.parse(SECRET_JWK));

        assertTrue(keySet.keyWithId("1") instanceof RsaJsonWebKey);
        assertTrue(keySet.keyWithId("2") instanceof SecretJsonWebKey);
        assertNull(keySet.keyWithId("3"));
        assertNull(keySet.keyWithId(null));
    }
}
