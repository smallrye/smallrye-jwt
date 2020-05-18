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

import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

import javax.crypto.SecretKey;

import org.jose4j.base64url.Base64Url;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.EllipticCurves;
import org.junit.Assert;
import org.junit.Test;

import io.smallrye.jwt.KeyUtils;
import io.smallrye.jwt.algorithm.ContentEncryptionAlgorithm;

public class JwtEncryptTest {

    @Test
    public void testEncryptWithRsaPublicKey() throws Exception {
        String jweCompact = Jwt.claims()
                .claim("customClaim", "custom-value")
                .jwe()
                .keyEncryptionKeyId("key-enc-key-id")
                .encrypt();

        checkJweHeaders(jweCompact);

        JsonWebEncryption jwe = getJsonWebEncryption(jweCompact);

        JwtClaims claims = JwtClaims.parse(jwe.getPlaintextString());
        checkJwtClaims(claims);
    }

    @Test
    public void testEncryptWithRsaPublicKeyLocation() throws Exception {
        String jweCompact = Jwt.claims()
                .claim("customClaim", "custom-value")
                .jwe()
                .keyEncryptionKeyId("key-enc-key-id")
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
                .keyEncryptionKeyId("key-enc-key-id")
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
                .keyEncryptionKeyId("key-enc-key-id")
                .contentEncryptionAlgorithm(ContentEncryptionAlgorithm.A128CBC_HS256)
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
                .keyEncryptionKeyId("key-enc-key-id")
                .encrypt(createSecretKey());

        checkJweHeaders(jweCompact, "A256KW", 3);

        JsonWebEncryption jwe = getJsonWebEncryption(jweCompact, createSecretKey());

        JwtClaims claims = JwtClaims.parse(jwe.getPlaintextString());
        checkJwtClaims(claims);
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
