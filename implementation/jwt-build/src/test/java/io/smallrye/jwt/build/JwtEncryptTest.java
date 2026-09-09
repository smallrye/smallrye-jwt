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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import jakarta.json.Json;
import jakarta.json.JsonObject;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.AESDecrypter;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.PasswordBasedDecrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;

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

        JWEObject jwe = getDecryptedJwe(jweCompact);

        JWTClaimsSet claims = JWTClaimsSet.parse(jwe.getPayload().toString());
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

            JWEObject jwe = getDecryptedJwe(jweCompact);

            JWTClaimsSet claims = JWTClaimsSet.parse(jwe.getPayload().toString());
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

            JWEObject jwe = getDecryptedJwe(jweCompact, decryptionKey);

            JWTClaimsSet claims = JWTClaimsSet.parse(jwe.getPayload().toString());
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
    void encryptJsonString() throws Exception {
        String jweCompact = Jwt.claimsJson("{\"customClaim\":\"custom-value\"}")
                .jwe().encrypt();

        doTestEncryptedClaims(jweCompact);
    }

    @Test
    void encryptJsonStringShortcut() throws Exception {
        String jweCompact = Jwt.encryptJson("{\"customClaim\":\"custom-value\"}");

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
        JWEObject jwe = getDecryptedJwe(jweCompact);
        JWTClaimsSet claims = JWTClaimsSet.parse(jwe.getPayload().toString());
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

        JWEObject jwe = getDecryptedJwe(jweCompact);

        JWTClaimsSet claims = JWTClaimsSet.parse(jwe.getPayload().toString());
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

        JWEObject jwe = getDecryptedJwe(jweCompact);

        JWTClaimsSet claims = JWTClaimsSet.parse(jwe.getPayload().toString());
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

        JWEObject jwe = getDecryptedJwe(jweCompact);

        JWTClaimsSet claims = JWTClaimsSet.parse(jwe.getPayload().toString());
        checkJwtClaims(claims);
    }

    @Test
    void encryptWithShortRSAKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        // Nimbus RSAEncrypter does not validate RSA key size, so encryption succeeds
        String jweCompact = Jwt.claims().jwe().encrypt(keyPair.getPublic());
        assertNotNull(jweCompact);
    }

    @SuppressWarnings("deprecation")
    @Test
    void encryptWithShortRSAKeyAndRelaxedValidation() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair(1024);

        JwtBuildConfigSource configSource = JwtSignTest.getConfigSource();
        configSource.setRelaxEncryptionKeyValidation(true);
        try {
            String jwt = Jwt.claims(Collections.singletonMap("customClaim", "custom-value"))
                    .jwe().encrypt(keyPair.getPublic());

            JWEObject jwe = JWEObject.parse(jwt);
            jwe.decrypt(new RSADecrypter(keyPair.getPrivate(), null, true));
            JWTClaimsSet claims = JWTClaimsSet.parse(jwe.getPayload().toString());
            checkJwtClaims(claims);
        } finally {
            configSource.setRelaxEncryptionKeyValidation(false);
        }
    }

    @Test
    void encryptWithEcKey() throws Exception {
        ECKey ecJwk = createECJwk();
        String jweCompact = Jwt.claims()
                .claim("customClaim", "custom-value")
                .jwe()
                .keyId("key-enc-key-id")
                .encrypt(ecJwk.toECPublicKey());

        checkJweHeaders(jweCompact, "ECDH-ES+A256KW", 4);

        JWEObject jwe = getDecryptedJwe(jweCompact, ecJwk.toECPrivateKey());

        JWTClaimsSet claims = JWTClaimsSet.parse(jwe.getPayload().toString());
        checkJwtClaims(claims);
    }

    @Test
    void encryptWithEcKeyX25519() throws Exception {
        if (Runtime.version().version().get(0) >= 17) {
            KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("X25519");
            KeyPair kp = kpg.generateKeyPair();
            String jweCompact = Jwt.claims()
                    .claim("customClaim", "custom-value")
                    .jwe()
                    .keyId("key-enc-key-id")
                    .encrypt(kp.getPublic());

            checkJweHeaders(jweCompact, "ECDH-ES+A256KW", 4);

            JWEObject jwe = JWEObject.parse(jweCompact);
            jwe.decrypt(new io.smallrye.jwt.algorithm.XDHDecrypter(kp.getPrivate(), Curve.X25519));

            JWTClaimsSet claims = JWTClaimsSet.parse(jwe.getPayload().toString());
            checkJwtClaims(claims);
        }
    }

    @Test
    void encryptWithEcKeyX448() throws Exception {
        if (Runtime.version().version().get(0) >= 17) {
            KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("X448");
            KeyPair kp = kpg.generateKeyPair();
            String jweCompact = Jwt.claims()
                    .claim("customClaim", "custom-value")
                    .jwe()
                    .keyId("key-enc-key-id")
                    .encrypt(kp.getPublic());

            checkJweHeaders(jweCompact, "ECDH-ES+A256KW", 4);

            JWEObject jwe = JWEObject.parse(jweCompact);
            jwe.decrypt(new io.smallrye.jwt.algorithm.XDHDecrypter(kp.getPrivate(), Curve.X448));

            JWTClaimsSet claims = JWTClaimsSet.parse(jwe.getPayload().toString());
            checkJwtClaims(claims);
        }
    }

    @Test
    void encryptWithEcKeyAndA128CBCHS256() throws Exception {
        ECKey ecJwk = createECJwk();
        String jweCompact = Jwt.claims()
                .claim("customClaim", "custom-value")
                .jwe()
                .keyId("key-enc-key-id")
                .contentAlgorithm(ContentEncryptionAlgorithm.A128CBC_HS256)
                .type("custom/jwe")
                .encrypt(ecJwk.toECPublicKey());

        checkJweHeaders(jweCompact, "ECDH-ES+A256KW", "A128CBC-HS256", "custom/jwe", 5);

        JWEObject jwe = getDecryptedJwe(jweCompact, ecJwk.toECPrivateKey());

        JWTClaimsSet claims = JWTClaimsSet.parse(jwe.getPayload().toString());
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

        JWEObject jwe = getDecryptedJwe(jweCompact, getEcPrivateKey());

        JWTClaimsSet claims = JWTClaimsSet.parse(jwe.getPayload().toString());
        checkJwtClaims(claims);
    }

    @Test
    void encryptWithConfiguredEcKeyAndAlgorithmAndA128CBCHS256() throws Exception {
        JwtBuildConfigSource configSource = JwtSignTest.getConfigSource();
        configSource.setEncryptionKeyLocation("/ecPublicKey.pem");
        configSource.setKeyEncryptionAlgorithm("ECDH-ES+A256KW");
        String jweCompact = null;
        try {
            jweCompact = Jwt.claims()
                    .claim("customClaim", "custom-value")
                    .jwe()
                    .keyId("key-enc-key-id")
                    .contentAlgorithm(ContentEncryptionAlgorithm.A128CBC_HS256)
                    .encrypt();
        } finally {
            configSource.setEncryptionKeyLocation("/publicKey.pem");
            configSource.setKeyEncryptionAlgorithm(null);
        }

        checkJweHeaders(jweCompact, "ECDH-ES+A256KW", "A128CBC-HS256", 4);

        JWEObject jwe = getDecryptedJwe(jweCompact, getEcPrivateKey());

        JWTClaimsSet claims = JWTClaimsSet.parse(jwe.getPayload().toString());
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

        JWEObject jwe = getDecryptedJwe(jweCompact, getEcPrivateKey());

        JWTClaimsSet claims = JWTClaimsSet.parse(jwe.getPayload().toString());
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

        JWEObject jwe = getDecryptedJwe(jweCompact, createSecretKey());

        JWTClaimsSet claims = JWTClaimsSet.parse(jwe.getPayload().toString());
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

        JWEObject jwe = getDecryptedJwe(jweCompact, createSecretKey());

        JWTClaimsSet claims = JWTClaimsSet.parse(jwe.getPayload().toString());
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
        JWEObject jwe = getDecryptedJwe(jweCompact, secretKey);

        JWTClaimsSet claims = JWTClaimsSet.parse(jwe.getPayload().toString());
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
        JWEObject jwe = JWEObject.parse(jweCompact);
        jwe.decrypt(new DirectDecrypter(secretKey));

        JWTClaimsSet claims = JWTClaimsSet.parse(jwe.getPayload().toString());
        checkJwtClaims(claims);
    }

    @Test
    void encryptWithSecretKeyAndUseDirAlgoJwk() throws Exception {
        String jweCompact = Jwt.claims()
                .claim("customClaim", "custom-value")
                .jwe()
                .keyId("key-enc-key-id")
                .keyAlgorithm(KeyEncryptionAlgorithm.DIR)
                .encrypt("secretKey.jwk");

        checkJweHeaders(jweCompact, "dir", 3);

        Key secretKey = KeyUtils.readEncryptionKey("/secretKey.jwk", null, null);
        JWEObject jwe = JWEObject.parse(jweCompact);
        jwe.decrypt(new DirectDecrypter((SecretKey) secretKey));

        JWTClaimsSet claims = JWTClaimsSet.parse(jwe.getPayload().toString());
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

        JWEObject jwe = JWEObject.parse(jweCompact);
        jwe.decrypt(new PasswordBasedDecrypter(secret));

        JWTClaimsSet claims = JWTClaimsSet.parse(jwe.getPayload().toString());
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

    private static void checkJwtClaims(JWTClaimsSet claims) throws Exception {
        assertEquals(4, claims.getClaims().size());
        assertNotNull(claims.getIssueTime());
        assertNotNull(claims.getExpirationTime());
        assertNotNull(claims.getJWTID());
        assertEquals("custom-value", claims.getClaim("customClaim"));
    }

    private static void checkJweHeaders(String jweCompact) throws Exception {
        checkJweHeaders(jweCompact, "RSA-OAEP", 3);
    }

    private static void checkJweHeaders(String jweCompact, String keyEncKeyAlg, int size) throws Exception {
        checkJweHeaders(jweCompact, keyEncKeyAlg, "A256GCM", size);
    }

    private static void checkJweHeaders(String jweCompact, String keyEncKeyAlg, String contentEncAlg, int size)
            throws Exception {
        checkJweHeaders(jweCompact, keyEncKeyAlg, contentEncAlg, null, size);
    }

    private static void checkJweHeaders(String jweCompact, String keyEncKeyAlg, String contentEncAlg, String type, int size)
            throws Exception {
        Map<String, Object> jweHeaders = getJweHeaders(jweCompact);
        assertEquals(size, jweHeaders.size());
        assertEquals(keyEncKeyAlg, jweHeaders.get("alg"));
        assertEquals(contentEncAlg, jweHeaders.get("enc"));
        assertEquals("key-enc-key-id", jweHeaders.get("kid"));
        if (type != null) {
            assertEquals(type, jweHeaders.get("typ"));
        } else {
            assertNull(jweHeaders.get("typ"));
        }
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

    private static JWEObject getDecryptedJwe(String compactJwe) throws Exception {
        return getDecryptedJwe(compactJwe, getPrivateKey());
    }

    private static JWEObject getDecryptedJwe(String compactJwe, Key decryptionKey) throws Exception {
        JWEObject jwe = JWEObject.parse(compactJwe);
        String alg = jwe.getHeader().getAlgorithm().getName();
        if (decryptionKey instanceof RSAPrivateKey) {
            jwe.decrypt(new RSADecrypter((RSAPrivateKey) decryptionKey));
        } else if (decryptionKey instanceof ECPrivateKey) {
            jwe.decrypt(new ECDHDecrypter((ECPrivateKey) decryptionKey));
        } else if (decryptionKey instanceof SecretKey) {
            if ("dir".equals(alg)) {
                jwe.decrypt(new DirectDecrypter((SecretKey) decryptionKey));
            } else {
                jwe.decrypt(new AESDecrypter((SecretKey) decryptionKey));
            }
        } else {
            throw new IllegalArgumentException("Unsupported key type: " + decryptionKey.getClass().getName());
        }
        return jwe;
    }

    private static Map<String, Object> getJweHeaders(String compactJwe) throws Exception {
        int firstDot = compactJwe.indexOf(".");
        String headersJson = new Base64URL(compactJwe.substring(0, firstDot)).decodeToString();
        return JSONObjectUtils.parse(headersJson);
    }

    private static SecretKey createSecretKey() throws Exception {
        String jwkJson = "{\"kty\":\"oct\",\"k\":\"Fdh9u8rINxfivbrianbbVT1u232VQBZYKx1HGAGPt2I\"}";
        OctetSequenceKey jwk = OctetSequenceKey.parse(jwkJson);
        return jwk.toSecretKey("AES");
    }

    private static ECKey createECJwk() throws Exception {
        return new ECKeyGenerator(Curve.P_256).generate();
    }
}
