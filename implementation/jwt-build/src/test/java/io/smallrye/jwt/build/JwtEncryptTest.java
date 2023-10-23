/*
 *   Copyright 2019 Red Hat, Inc, and individual contributors.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */
package io.smallrye.jwt.build;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import jakarta.json.Json;
import jakarta.json.JsonObject;

import org.jose4j.base64url.Base64Url;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OctetKeyPairJsonWebKey;
import org.jose4j.jwk.OkpJwkGenerator;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.keys.PbkdfKey;
import org.junit.jupiter.api.Test;

import io.smallrye.jwt.algorithm.ContentEncryptionAlgorithm;
import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.jwt.util.KeyUtils;

public class JwtEncryptTest {
    @Test
    void encryptWithRsaPublicKey() throws Exception {
        String jweCompact = Jwt.claims()
                .claim("customClaim", "custom-value")
                .jwe()
                .keyId("key-enc-key-id")
                .encrypt();

        checkJweHeaders(jweCompact);

        JsonWebEncryption jwe = getJsonWebEncryption(jweCompact);

        JwtClaims claims = JwtClaims.parse(jwe.getPlaintextString());
        checkJwtClaims(claims);
    }

    @Test
    void encryptWithRsaPublicKeyContent() throws Exception {
        JwtBuildConfigSource configSource = JwtSignTest.getConfigSource();
        configSource.setUseEncryptionKeyProperty(true);
        try {
            String jweCompact = Jwt.claims()
                    .claim("customClaim", "custom-value")
                    .jwe()
                    .keyId("key-enc-key-id")
                    .encrypt();

            checkJweHeaders(jweCompact);

            JsonWebEncryption jwe = getJsonWebEncryption(jweCompact);

            JwtClaims claims = JwtClaims.parse(jwe.getPlaintextString());
            checkJwtClaims(claims);
        } finally {
            configSource.setUseEncryptionKeyProperty(false);
        }
    }

    @Test
    void encryptWithKeyStore() throws Exception {
        JwtBuildConfigSource configSource = JwtSignTest.getConfigSource();
        configSource.setUseKeyStore(true);
        configSource.setEncryptionKeyLocation("/keystore.p12");

        try {
            String jweCompact = Jwt.claims()
                    .claim("customClaim", "custom-value")
                    .jwe()
                    .keyId("key-enc-key-id")
                    .encrypt();

            checkJweHeaders(jweCompact);

            KeyStore keyStore = KeyUtils.loadKeyStore("keystore.p12", "password", Optional.empty(), Optional.empty());
            PrivateKey decryptionKey = (PrivateKey) keyStore.getKey("server", "password".toCharArray());

            JsonWebEncryption jwe = getJsonWebEncryption(jweCompact, decryptionKey);

            JwtClaims claims = JwtClaims.parse(jwe.getPlaintextString());
            checkJwtClaims(claims);
        } finally {
            configSource.setUseKeyStore(false);
            configSource.setEncryptionKeyLocation("/publicKey.pem");
        }
    }

    @Test
    void encryptMapOfClaims() throws Exception {
        String jweCompact = Jwt.claims(Collections.singletonMap("customClaim", "custom-value"))
                .jwe().encrypt();

        doTestEncryptedClaims(jweCompact);
    }

    @Test
    void encryptMapOfClaimsShortcut() throws Exception {
        String jweCompact = Jwt.encrypt(Collections.singletonMap("customClaim", "custom-value"));

        doTestEncryptedClaims(jweCompact);
    }

    @Test
    void encryptJsonObject() throws Exception {
        JsonObject json = Json.createObjectBuilder().add("customClaim", "custom-value").build();
        String jweCompact = Jwt.claims(json).jwe().encrypt();

        doTestEncryptedClaims(jweCompact);
    }

    @Test
    void encryptJsonObjectShortcut() throws Exception {
        JsonObject json = Json.createObjectBuilder().add("customClaim", "custom-value").build();
        String jweCompact = Jwt.encrypt(json);

        doTestEncryptedClaims(jweCompact);
    }

    @Test
    void encryptExistingClaims() throws Exception {
        doTestEncryptedClaims(Jwt.claims("/customClaim.json").jwe().encrypt());
    }

    @Test
    void encryptExistingClaimsShortcut() throws Exception {
        doTestEncryptedClaims(Jwt.encrypt("/customClaim.json"));
    }

    private void doTestEncryptedClaims(String jweCompact) throws Exception {
        checkRsaEncJweHeaders(jweCompact);
        JsonWebEncryption jwe = getJsonWebEncryption(jweCompact);
        JwtClaims claims = JwtClaims.parse(jwe.getPlaintextString());
        checkJwtClaims(claims);
    }

    @Test
    void encryptWithRsaPublicKeyLocation() throws Exception {
        String jweCompact = Jwt.claims()
                .claim("customClaim", "custom-value")
                .jwe()
                .keyId("key-enc-key-id")
                .encrypt("publicKey.pem");

        checkJweHeaders(jweCompact);

        JsonWebEncryption jwe = getJsonWebEncryption(jweCompact);

        JwtClaims claims = JwtClaims.parse(jwe.getPlaintextString());
        checkJwtClaims(claims);
    }

    @Test
    void encryptWithRsaOaep256() throws Exception {
        String jweCompact = Jwt.claims()
                .claim("customClaim", "custom-value")
                .jwe().keyAlgorithm(KeyEncryptionAlgorithm.RSA_OAEP_256)
                .keyId("key-enc-key-id")
                .encrypt("publicKey.pem");

        checkJweHeaders(jweCompact, "RSA-OAEP-256", 3);

        JsonWebEncryption jwe = getJsonWebEncryption(jweCompact);

        JwtClaims claims = JwtClaims.parse(jwe.getPlaintextString());
        checkJwtClaims(claims);
    }

    @Test
    void encryptWithRsaOaep256Configured() throws Exception {
        JwtBuildConfigSource configSource = JwtSignTest.getConfigSource();
        configSource.setKeyEncryptionAlgorithm("RSA_OAEP_256");
        String jweCompact = null;
        try {
            jweCompact = Jwt.claims()
                    .claim("customClaim", "custom-value")
                    .jwe()
                    .keyId("key-enc-key-id")
                    .encrypt("publicKey.pem");
        } finally {
            configSource.setKeyEncryptionAlgorithm(null);
        }

        checkJweHeaders(jweCompact, "RSA-OAEP-256", 3);

        JsonWebEncryption jwe = getJsonWebEncryption(jweCompact);

        JwtClaims claims = JwtClaims.parse(jwe.getPlaintextString());
        checkJwtClaims(claims);
    }

    @Test
    void encryptWithShortRSAKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        PublicKey key = keyPairGenerator.generateKeyPair().getPublic();
        try {
            Jwt.claims().jwe().encrypt(key);
            fail("JwtEncryptionException is expected due to the invalid key size");
        } catch (JwtEncryptionException ex) {
            assertEquals(
                    "SRJWT05003: An RSA key of size 2048 bits or larger MUST be used with the all JOSE RSA algorithms (given key was only 1024 bits).",
                    ex.getMessage());
        }
    }

    @Test
    void encryptWithShortRSAKeyAndRelaxedValidation() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair(1024);

        JwtBuildConfigSource configSource = JwtSignTest.getConfigSource();
        configSource.setRelaxEncryptionKeyValidation(true);
        try {
            String jwt = Jwt.claims(Collections.singletonMap("customClaim", "custom-value"))
                    .jwe().encrypt(keyPair.getPublic());

            JsonWebEncryption jwe = getJsonWebEncryption(jwt, keyPair.getPrivate(), true);
            JwtClaims claims = JwtClaims.parse(jwe.getPlaintextString());
            checkJwtClaims(claims);
        } finally {
            configSource.setRelaxEncryptionKeyValidation(false);
        }
    }

    @Test
    void encryptWithEcKey() throws Exception {
        EllipticCurveJsonWebKey jwk = createECJwk();
        String jweCompact = Jwt.claims()
                .claim("customClaim", "custom-value")
                .jwe()
                .keyId("key-enc-key-id")
                .encrypt(jwk.getECPublicKey());

        checkJweHeaders(jweCompact, "ECDH-ES+A256KW", 4);

        JsonWebEncryption jwe = getJsonWebEncryption(jweCompact, jwk.getEcPrivateKey());

        JwtClaims claims = JwtClaims.parse(jwe.getPlaintextString());
        checkJwtClaims(claims);
    }

    @Test
    void encryptWithEcKeyX25519() throws Exception {
        if (Runtime.version().version().get(0) >= 17) {
            OctetKeyPairJsonWebKey jwk = OkpJwkGenerator.generateJwk(OctetKeyPairJsonWebKey.SUBTYPE_X25519);
            String jweCompact = Jwt.claims()
                    .claim("customClaim", "custom-value")
                    .jwe()
                    .keyId("key-enc-key-id")
                    .encrypt(jwk.getPublicKey());

            checkJweHeaders(jweCompact, "ECDH-ES+A256KW", 4);

            JsonWebEncryption jwe = getJsonWebEncryption(jweCompact, jwk.getPrivateKey());

            JwtClaims claims = JwtClaims.parse(jwe.getPlaintextString());
            checkJwtClaims(claims);
        }
    }

    @Test
    void encryptWithEcKeyX448() throws Exception {
        if (Runtime.version().version().get(0) >= 17) {
            OctetKeyPairJsonWebKey jwk = OkpJwkGenerator.generateJwk(OctetKeyPairJsonWebKey.SUBTYPE_X448);
            String jweCompact = Jwt.claims()
                    .claim("customClaim", "custom-value")
                    .jwe()
                    .keyId("key-enc-key-id")
                    .encrypt(jwk.getPublicKey());

            checkJweHeaders(jweCompact, "ECDH-ES+A256KW", 4);

            JsonWebEncryption jwe = getJsonWebEncryption(jweCompact, jwk.getPrivateKey());

            JwtClaims claims = JwtClaims.parse(jwe.getPlaintextString());
            checkJwtClaims(claims);
        }
    }

    @Test
    void encryptWithEcKeyAndA128CBCHS256() throws Exception {
        EllipticCurveJsonWebKey jwk = createECJwk();
        String jweCompact = Jwt.claims()
                .claim("customClaim", "custom-value")
                .jwe()
                .keyId("key-enc-key-id")
                .contentAlgorithm(ContentEncryptionAlgorithm.A128CBC_HS256)
                .encrypt(jwk.getECPublicKey());

        checkJweHeaders(jweCompact, "ECDH-ES+A256KW", "A128CBC-HS256", 4);

        JsonWebEncryption jwe = getJsonWebEncryption(jweCompact, jwk.getEcPrivateKey());

        JwtClaims claims = JwtClaims.parse(jwe.getPlaintextString());
        checkJwtClaims(claims);
    }

    @Test
    void encryptWithConfiguredEcKeyAndA128CBCHS256() throws Exception {
        JwtBuildConfigSource configSource = JwtSignTest.getConfigSource();
        configSource.setEncryptionKeyLocation("/ecPublicKey.pem");
        String jweCompact = null;
        try {
            jweCompact = Jwt.claims()
                    .claim("customClaim", "custom-value")
                    .jwe()
                    .keyId("key-enc-key-id")
                    .keyAlgorithm(KeyEncryptionAlgorithm.ECDH_ES_A256KW)
                    .contentAlgorithm(ContentEncryptionAlgorithm.A128CBC_HS256)
                    .encrypt();
        } finally {
            configSource.setEncryptionKeyLocation("/publicKey.pem");
        }

        checkJweHeaders(jweCompact, "ECDH-ES+A256KW", "A128CBC-HS256", 4);

        JsonWebEncryption jwe = getJsonWebEncryption(jweCompact, getEcPrivateKey());

        JwtClaims claims = JwtClaims.parse(jwe.getPlaintextString());
        checkJwtClaims(claims);
    }

    @Test
    void encryptWithConfiguredEcKeyAndContentAlgorithm() throws Exception {
        JwtBuildConfigSource configSource = JwtSignTest.getConfigSource();
        configSource.setEncryptionKeyLocation("/ecPublicKey.pem");
        configSource.setContentEncryptionAlgorithm("A128CBC-HS256");
        String jweCompact = null;
        try {
            jweCompact = Jwt.claims()
                    .claim("customClaim", "custom-value")
                    .jwe()
                    .keyId("key-enc-key-id")
                    .keyAlgorithm(KeyEncryptionAlgorithm.ECDH_ES_A256KW)
                    .encrypt();
        } finally {
            configSource.setEncryptionKeyLocation("/publicKey.pem");
            configSource.setContentEncryptionAlgorithm(null);
        }

        checkJweHeaders(jweCompact, "ECDH-ES+A256KW", "A128CBC-HS256", 4);

        JsonWebEncryption jwe = getJsonWebEncryption(jweCompact, getEcPrivateKey());

        JwtClaims claims = JwtClaims.parse(jwe.getPlaintextString());
        checkJwtClaims(claims);
    }

    @Test
    void encryptWithSecretKey() throws Exception {
        String jweCompact = Jwt.claims()
                .claim("customClaim", "custom-value")
                .jwe()
                .keyId("key-enc-key-id")
                .encrypt(createSecretKey());

        checkJweHeaders(jweCompact, "A256KW", 3);

        JsonWebEncryption jwe = getJsonWebEncryption(jweCompact, createSecretKey());

        JwtClaims claims = JwtClaims.parse(jwe.getPlaintextString());
        checkJwtClaims(claims);
    }

    @Test
    void encryptWithSecretKeyAndGsmKeyWrap() throws Exception {
        String jweCompact = Jwt.claims()
                .claim("customClaim", "custom-value")
                .jwe()
                .keyId("key-enc-key-id")
                .keyAlgorithm(KeyEncryptionAlgorithm.A256GCMKW)
                .encrypt(createSecretKey());

        checkJweHeaders(jweCompact, "A256GCMKW", 5);

        JsonWebEncryption jwe = getJsonWebEncryption(jweCompact, createSecretKey());

        JwtClaims claims = JwtClaims.parse(jwe.getPlaintextString());
        checkJwtClaims(claims);
    }

    @Test
    void encryptWithSecret() throws Exception {
        String secret = "AyM1SysPpbyDfgZld3umj1qzKObwVMko";

        String jweCompact = Jwt.claims()
                .claim("customClaim", "custom-value")
                .jwe().keyId("key-enc-key-id")
                .encryptWithSecret(secret);

        checkJweHeaders(jweCompact, "A256KW", 3);

        SecretKey secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "AES");
        JsonWebEncryption jwe = getJsonWebEncryption(jweCompact, secretKey);

        JwtClaims claims = JwtClaims.parse(jwe.getPlaintextString());
        checkJwtClaims(claims);
    }

    @Test
    void encryptWithSecretKeyAndUseDirAlgo() throws Exception {
        String secret = "AyM1SysPpbyDfgZld3umj1qzKObwVMko";

        String jweCompact = Jwt.claims()
                .claim("customClaim", "custom-value")
                .jwe()
                .keyId("key-enc-key-id")
                .keyAlgorithm(KeyEncryptionAlgorithm.DIR)
                .encryptWithSecret(secret);

        checkJweHeaders(jweCompact, "dir", 3);

        SecretKey secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "AES");
        JsonWebEncryption jwe = getJsonWebEncryption(jweCompact, secretKey);

        JwtClaims claims = JwtClaims.parse(jwe.getPlaintextString());
        checkJwtClaims(claims);
    }

    @Test
    void encryptWithSecretPassword() throws Exception {
        String secret = "AyM1SysPpbyDfgZld3umj1qzKObwVMko";

        String jweCompact = Jwt.claims()
                .claim("customClaim", "custom-value")
                .jwe().keyAlgorithm(KeyEncryptionAlgorithm.PBES2_HS256_A128KW)
                .keyId("key-enc-key-id")
                .encryptWithSecret(secret);

        checkJweHeaders(jweCompact, "PBES2-HS256+A128KW", 5);

        SecretKey secretKey = new PbkdfKey("AyM1SysPpbyDfgZld3umj1qzKObwVMko");
        JsonWebEncryption jwe = getJsonWebEncryption(jweCompact, secretKey);

        JwtClaims claims = JwtClaims.parse(jwe.getPlaintextString());
        checkJwtClaims(claims);
    }

    @Test
    void encryptWithInvalidKeyLocation() {
        JwtClaimsBuilder builder = Jwt.claims();

        JwtEncryptionException thrown = assertThrows(JwtEncryptionException.class,
                () -> builder.jwe().encrypt("/invalid-key-location.pem"), "JwtEncryptionException is expected");
        assertTrue(thrown.getCause()
                .getMessage().contains("Key encryption key can not be loaded from: /invalid-key-location.pem"));
    }

    private static PrivateKey getPrivateKey() throws Exception {
        return KeyUtils.readPrivateKey("/privateKey.pem");
    }

    private static PrivateKey getEcPrivateKey() throws Exception {
        return KeyUtils.readDecryptionPrivateKey("/ecPrivateKey.pem", KeyEncryptionAlgorithm.ECDH_ES_A256KW);
    }

    private static void checkJwtClaims(JwtClaims claims) throws Exception {
        assertEquals(4, claims.getClaimsMap().size());
        assertNotNull(claims.getIssuedAt());
        assertNotNull(claims.getExpirationTime());
        assertNotNull(claims.getJwtId());
        assertEquals("custom-value", claims.getClaimValue("customClaim"));
    }

    private static void checkJweHeaders(String jweCompact) throws Exception {
        checkJweHeaders(jweCompact, "RSA-OAEP", 3);
    }

    private static void checkJweHeaders(String jweCompact, String keyEncKeyAlg, int size) throws Exception {
        checkJweHeaders(jweCompact, keyEncKeyAlg, "A256GCM", size);
    }

    private static void checkJweHeaders(String jweCompact, String keyEncKeyAlg, String contentEncAlg, int size)
            throws Exception {
        Map<String, Object> jweHeaders = getJweHeaders(jweCompact);
        assertEquals(size, jweHeaders.size());
        assertEquals(keyEncKeyAlg, jweHeaders.get("alg"));
        assertEquals(contentEncAlg, jweHeaders.get("enc"));
        assertEquals("key-enc-key-id", jweHeaders.get("kid"));
        if ("ECDH-ES+A256KW".equals(keyEncKeyAlg)) {
            assertNotNull(jweHeaders.get("epk"));
        }
        if ("A256GCMKW".equals(keyEncKeyAlg)) {
            assertNotNull(jweHeaders.get("iv"));
            assertNotNull(jweHeaders.get("tag"));
        }
    }

    private static void checkRsaEncJweHeaders(String jweCompact) throws Exception {
        Map<String, Object> jweHeaders = getJweHeaders(jweCompact);
        assertEquals(2, jweHeaders.size());
        assertEquals("RSA-OAEP", jweHeaders.get("alg"));
        assertEquals("A256GCM", jweHeaders.get("enc"));
    }

    private static JsonWebEncryption getJsonWebEncryption(String compactJwe) throws Exception {
        return getJsonWebEncryption(compactJwe, getPrivateKey());
    }

    private static JsonWebEncryption getJsonWebEncryption(String compactJwe, Key decryptionKey) throws Exception {
        return getJsonWebEncryption(compactJwe, decryptionKey, false);
    }

    private static JsonWebEncryption getJsonWebEncryption(String compactJwe, Key decryptionKey, boolean relaxKeyValidation)
            throws Exception {
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setCompactSerialization(compactJwe);
        jwe.setKey(decryptionKey);
        if (relaxKeyValidation) {
            jwe.setDoKeyValidation(false);
        }
        return jwe;
    }

    private static Map<String, Object> getJweHeaders(String compactJwe) throws Exception {
        int firstDot = compactJwe.indexOf(".");
        String headersJson = new Base64Url().base64UrlDecodeToUtf8String(compactJwe.substring(0, firstDot));
        return JsonUtil.parseJson(headersJson);
    }

    private static SecretKey createSecretKey() throws Exception {
        String jwkJson = "{\"kty\":\"oct\",\"k\":\"Fdh9u8rINxfivbrianbbVT1u232VQBZYKx1HGAGPt2I\"}";
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(jwkJson);
        return (SecretKey) jwk.getKey();
    }

    private static EllipticCurveJsonWebKey createECJwk() throws Exception {
        return EcJwkGenerator.generateJwk(EllipticCurves.P256);
    }
}
