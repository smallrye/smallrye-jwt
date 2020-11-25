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

import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.json.Json;
import javax.json.JsonObject;

import org.jose4j.base64url.Base64Url;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.keys.PbkdfKey;
import org.junit.Assert;
import org.junit.Test;

import io.smallrye.jwt.algorithm.ContentEncryptionAlgorithm;
import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.jwt.util.KeyUtils;

public class JwtEncryptTest {

    @Test
    public void testEncryptWithRsaPublicKey() throws Exception {
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
    public void testEncryptMapOfClaims() throws Exception {
        String jweCompact = Jwt.claims(Collections.singletonMap("customClaim", "custom-value"))
                .jwe().encrypt();

        doTestEncryptedClaims(jweCompact);
    }

    @Test
    public void testEncryptMapOfClaimsShortcut() throws Exception {
        String jweCompact = Jwt.encrypt(Collections.singletonMap("customClaim", "custom-value"));

        doTestEncryptedClaims(jweCompact);
    }

    @Test
    public void testEncryptJsonObject() throws Exception {
        JsonObject json = Json.createObjectBuilder().add("customClaim", "custom-value").build();
        String jweCompact = Jwt.claims(json).jwe().encrypt();

        doTestEncryptedClaims(jweCompact);
    }

    @Test
    public void testEncryptJsonObjectShortcut() throws Exception {
        JsonObject json = Json.createObjectBuilder().add("customClaim", "custom-value").build();
        String jweCompact = Jwt.encrypt(json);

        doTestEncryptedClaims(jweCompact);
    }

    @Test
    public void testEncryptExistingClaims() throws Exception {
        doTestEncryptedClaims(Jwt.claims("/customClaim.json").jwe().encrypt());
    }

    @Test
    public void testEncryptExistingClaimsShortcut() throws Exception {
        doTestEncryptedClaims(Jwt.encrypt("/customClaim.json"));
    }

    private void doTestEncryptedClaims(String jweCompact) throws Exception {
        checkRsaEncJweHeaders(jweCompact);
        JsonWebEncryption jwe = getJsonWebEncryption(jweCompact);
        JwtClaims claims = JwtClaims.parse(jwe.getPlaintextString());
        checkJwtClaims(claims);
    }

    @Test
    public void testEncryptWithRsaPublicKeyLocation() throws Exception {
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
    public void testEncryptWithInvalidRSAKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        PublicKey key = keyPairGenerator.generateKeyPair().getPublic();
        try {
            Jwt.claims().jwe().encrypt(key);
            Assert.fail("JwtEncryptionException is expected due to the invalid key size");
        } catch (JwtEncryptionException ex) {
            Assert.assertEquals("SRJWT05001: A key of size 2048 bits or larger MUST be used with the 'RSA-OAEP-256' algorithm",
                    ex.getMessage());
        }
    }

    @Test
    public void testEncryptWithEcKey() throws Exception {
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
    public void testEncryptWithEcKeyAndA128CBCHS256() throws Exception {
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
    public void testEncryptWithSecretKey() throws Exception {
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
    public void testEncryptWithSecret() throws Exception {
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
    public void testEncryptWithSecretPassword() throws Exception {
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
    public void testEncryptWithInvalidKeyLocation() throws Exception {
        JwtClaimsBuilder builder = Jwt.claims();

        JwtEncryptionException thrown = assertThrows("JwtEncryptionException is expected",
                JwtEncryptionException.class, () -> builder.jwe().encrypt("/invalid-key-location.pem"));
        assertTrue(thrown.getCause()
                .getMessage().contains("Key encryption key can not be loaded from: /invalid-key-location.pem"));
    }

    private static PrivateKey getPrivateKey() throws Exception {
        return KeyUtils.readPrivateKey("/privateKey.pem");
    }

    private static void checkJwtClaims(JwtClaims claims) throws Exception {
        Assert.assertEquals(4, claims.getClaimsMap().size());
        Assert.assertNotNull(claims.getIssuedAt());
        Assert.assertNotNull(claims.getExpirationTime());
        Assert.assertNotNull(claims.getJwtId());
        Assert.assertEquals("custom-value", claims.getClaimValue("customClaim"));
    }

    private static void checkJweHeaders(String jweCompact) throws Exception {
        checkJweHeaders(jweCompact, "RSA-OAEP-256", 3);
    }

    private static void checkJweHeaders(String jweCompact, String keyEncKeyAlg, int size) throws Exception {
        checkJweHeaders(jweCompact, keyEncKeyAlg, "A256GCM", size);
    }

    private static void checkJweHeaders(String jweCompact, String keyEncKeyAlg, String contentEncAlg, int size)
            throws Exception {
        Map<String, Object> jweHeaders = getJweHeaders(jweCompact);
        Assert.assertEquals(size, jweHeaders.size());
        Assert.assertEquals(keyEncKeyAlg, jweHeaders.get("alg"));
        Assert.assertEquals(contentEncAlg, jweHeaders.get("enc"));
        Assert.assertEquals("key-enc-key-id", jweHeaders.get("kid"));
        if ("ECDH-ES+A256KW".equals(keyEncKeyAlg)) {
            Assert.assertNotNull(jweHeaders.get("epk"));
        }
    }

    private static void checkRsaEncJweHeaders(String jweCompact) throws Exception {
        Map<String, Object> jweHeaders = getJweHeaders(jweCompact);
        Assert.assertEquals(2, jweHeaders.size());
        Assert.assertEquals("RSA-OAEP-256", jweHeaders.get("alg"));
        Assert.assertEquals("A256GCM", jweHeaders.get("enc"));
    }

    private static JsonWebEncryption getJsonWebEncryption(String compactJwe) throws Exception {
        return getJsonWebEncryption(compactJwe, getPrivateKey());
    }

    private static JsonWebEncryption getJsonWebEncryption(String compactJwe, Key decryptionKey) throws Exception {
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setCompactSerialization(compactJwe);
        jwe.setKey(decryptionKey);
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
