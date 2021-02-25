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

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.json.Json;
import javax.json.JsonObject;

import org.eclipse.microprofile.config.ConfigProvider;
import org.eclipse.microprofile.config.spi.ConfigSource;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jose4j.base64url.Base64Url;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;
import org.junit.Assert;
import org.junit.Test;

import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.util.KeyUtils;

public class JwtSignTest {

    @Test
    public void testSignClaims() throws Exception {
        signAndVerifyClaims();
    }

    @Test
    public void testSignClaimsCustomExpAndIssuerAndAud() throws Exception {
        JwtBuildConfigSource configSource = getConfigSource();
        try {
            configSource.setLifespanPropertyRequired(true);
            configSource.setIssuerPropertyRequired(true);
            configSource.setAudiencePropertyRequired(true);
            signAndVerifyClaims(2000L, "https://custom-issuer", "https://custom-audience");
        } finally {
            configSource.setLifespanPropertyRequired(false);
            configSource.setIssuerPropertyRequired(false);
            configSource.setAudiencePropertyRequired(false);
        }
    }

    @Test
    public void testEnhanceAndResignToken() throws Exception {
        JsonWebToken token = new TestJsonWebToken(signAndVerifyClaims());

        String jwt = Jwt.claims(token).claim("newClaim", "new-value").sign();

        // verify
        JsonWebSignature jws = getVerifiedJws(jwt);
        JwtClaims claims = JwtClaims.parse(jws.getPayload());
        Assert.assertEquals(7, claims.getClaimsMap().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);
        Assert.assertEquals("custom-value", claims.getClaimValue("customClaim"));

        Assert.assertEquals("new-value", claims.getClaimValue("newClaim"));
        Assert.assertEquals("https://default-issuer", claims.getIssuer());
        Assert.assertEquals(1, claims.getAudience().size());
        Assert.assertEquals("https://localhost:8081", claims.getAudience().get(0));
    }

    @Test
    public void testEnhanceAndResignTokenWithConfiguredIssuerAndAudUsed() throws Exception {
        JsonWebToken token = new TestJsonWebToken(signAndVerifyClaims());

        Assert.assertEquals("https://default-issuer", token.getIssuer());
        Assert.assertEquals(1, token.getAudience().size());
        Assert.assertEquals("https://localhost:8081", token.getAudience().iterator().next());

        JwtBuildConfigSource configSource = getConfigSource();
        configSource.setIssuerPropertyRequired(true);
        configSource.setAudiencePropertyRequired(true);
        configSource.setOverrideMatchingClaims(true);

        try {
            String jwt = Jwt.claims(token).claim("newClaim", "new-value").sign();

            // verify
            JsonWebSignature jws = getVerifiedJws(jwt);
            JwtClaims claims = JwtClaims.parse(jws.getPayload());
            Assert.assertEquals(7, claims.getClaimsMap().size());
            checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);
            Assert.assertEquals("custom-value", claims.getClaimValue("customClaim"));

            Assert.assertEquals("new-value", claims.getClaimValue("newClaim"));
            Assert.assertEquals("https://custom-issuer", claims.getIssuer());
            Assert.assertEquals(1, claims.getAudience().size());
            Assert.assertEquals("https://custom-audience", claims.getAudience().get(0));
        } finally {
            configSource.setIssuerPropertyRequired(false);
            configSource.setAudiencePropertyRequired(false);
            configSource.setOverrideMatchingClaims(false);
        }
    }

    private JwtClaims signAndVerifyClaims() throws Exception {
        return signAndVerifyClaims(null, null, null);
    }

    @SuppressWarnings("deprecation")
    private JwtClaims signAndVerifyClaims(Long customLifespan, String issuer, String aud) throws Exception {
        JwtClaimsBuilder builder = Jwt.claims().claim("customClaim", "custom-value");
        if (issuer == null) {
            builder.issuer("https://default-issuer");
        }
        if (aud == null) {
            builder.audience("https://localhost:8081");
        }
        String jsonBeforeSign = builder.json();
        String jwt = builder.sign(getPrivateKey());
        String jsonAfterSign = builder.json();
        Assert.assertEquals(jsonBeforeSign, jsonAfterSign);
        JsonWebSignature jws = getVerifiedJws(jwt);
        Assert.assertEquals(jsonAfterSign, jws.getPayload());
        JwtClaims claims = JwtClaims.parse(jws.getPayload());
        Assert.assertEquals(6, claims.getClaimsMap().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims, "RS256", customLifespan != null ? customLifespan : 300);

        Assert.assertEquals("custom-value", claims.getClaimValue("customClaim"));
        Assert.assertEquals((issuer == null ? "https://default-issuer" : issuer), claims.getIssuer());
        List<String> audiences = claims.getAudience();
        Assert.assertEquals(1, audiences.size());
        Assert.assertEquals((aud == null ? "https://localhost:8081" : aud), audiences.get(0));
        return claims;
    }

    @Test
    public void testCustomIssuedAtExpiresAtLong() throws Exception {
        Instant now = Instant.now();
        String jwt = Jwt.claims().issuedAt(now).expiresAt(now.getEpochSecond() + 3000).sign();
        verifyJwtCustomIssuedAtExpiresAt(now, jwt);
    }

    @Test
    public void testCustomIssuedAtExpiresAtInstant() throws Exception {
        Instant now = Instant.now();
        String jwt = Jwt.claims().issuedAt(now).expiresAt(now.plusSeconds(3000)).sign();
        verifyJwtCustomIssuedAtExpiresAt(now, jwt);
    }

    @Test
    public void testCustomIssuedAtExpiresInLong() throws Exception {
        Instant now = Instant.now();
        String jwt = Jwt.claims().issuedAt(now).expiresIn(3000).sign();
        verifyJwtCustomIssuedAtExpiresAt(now, jwt);
    }

    @Test
    public void testCustomIssuedAtExpiresInDuration() throws Exception {
        Instant now = Instant.now();
        String jwt = Jwt.claims().issuedAt(now).expiresIn(Duration.ofSeconds(3000)).sign();
        verifyJwtCustomIssuedAtExpiresAt(now, jwt);
    }

    private void verifyJwtCustomIssuedAtExpiresAt(Instant now, String jwt) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setKey(KeyUtils.readPublicKey("/publicKey.pem"));
        jws.setCompactSerialization(jwt);
        Assert.assertTrue(jws.verifySignature());
        JwtClaims claims = JwtClaims.parse(jws.getPayload());
        Assert.assertEquals(3, claims.getClaimsMap().size());
        Assert.assertEquals(now.getEpochSecond(), claims.getIssuedAt().getValue());
        Assert.assertEquals(now.getEpochSecond() + 3000, claims.getExpirationTime().getValue());
        Assert.assertNotNull(claims.getJwtId());
    }

    @Test
    public void testSignMapOfClaims() throws Exception {
        String jwt = Jwt.claims(Collections.singletonMap("customClaim", "custom-value"))
                .sign(getPrivateKey());

        JsonWebSignature jws = getVerifiedJws(jwt);
        JwtClaims claims = JwtClaims.parse(jws.getPayload());

        Assert.assertEquals(4, claims.getClaimsMap().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);

        Assert.assertEquals("custom-value", claims.getClaimValue("customClaim"));
    }

    @Test
    public void testSignMapOfClaimsShortcut() throws Exception {
        String jwt = Jwt.sign(Collections.singletonMap("customClaim", "custom-value"));

        JsonWebSignature jws = getVerifiedJws(jwt);
        JwtClaims claims = JwtClaims.parse(jws.getPayload());

        Assert.assertEquals(4, claims.getClaimsMap().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);

        Assert.assertEquals("custom-value", claims.getClaimValue("customClaim"));
    }

    @Test
    public void testSignMapOfClaimsWithKeyLocation() throws Exception {
        String jwt = Jwt.claims(Collections.singletonMap("customClaim", "custom-value"))
                .sign("/privateKey.pem");

        JsonWebSignature jws = getVerifiedJws(jwt);
        JwtClaims claims = JwtClaims.parse(jws.getPayload());

        Assert.assertEquals(4, claims.getClaimsMap().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);

        Assert.assertEquals("custom-value", claims.getClaimValue("customClaim"));
    }

    @Test
    public void testSignJsonObject() throws Exception {
        JsonObject userName = Json.createObjectBuilder().add("username", "Alice").build();
        JsonObject userAddress = Json.createObjectBuilder().add("city", "someCity").add("street", "someStreet").build();
        JsonObject json = Json.createObjectBuilder(userName).add("address", userAddress).build();

        String jwt = Jwt.claims(json).sign("/privateKey.pem");

        verifySignedJsonObject(jwt);
    }

    @Test
    public void testSignJsonObjectShortcut() throws Exception {
        JsonObject userName = Json.createObjectBuilder().add("username", "Alice").build();
        JsonObject userAddress = Json.createObjectBuilder().add("city", "someCity").add("street", "someStreet").build();
        JsonObject json = Json.createObjectBuilder(userName).add("address", userAddress).build();

        String jwt = Jwt.sign(json);

        verifySignedJsonObject(jwt);
    }

    private void verifySignedJsonObject(String jwt) throws Exception {
        JsonWebSignature jws = getVerifiedJws(jwt);
        JwtClaims claims = JwtClaims.parse(jws.getPayload());

        Assert.assertEquals(5, claims.getClaimsMap().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);

        Assert.assertEquals("Alice", claims.getClaimValue("username"));
        @SuppressWarnings("unchecked")
        Map<String, String> address = (Map<String, String>) claims.getClaimValue("address");
        Assert.assertEquals(2, address.size());
        Assert.assertEquals("someCity", address.get("city"));
        Assert.assertEquals("someStreet", address.get("street"));
    }

    @Test
    public void testSignWithInvalidRSAKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        PrivateKey key = keyPairGenerator.generateKeyPair().getPrivate();
        try {
            Jwt.claims().sign(key);
            Assert.fail("JwtSignatureException is expected due to the invalid key size");
        } catch (JwtSignatureException ex) {
            Assert.assertEquals(
                    "SRJWT05012: Failure to create a signed JWT token: An RSA key of size 2048 bits or larger MUST be used with the all JOSE RSA algorithms (given key was only 1024 bits).",
                    ex.getMessage());
        }
    }

    @Test
    public void testSignClaimsConfiguredKey() throws Exception {
        String jwt = Jwt.claims()
                .claim("customClaim", "custom-value")
                .sign();

        JsonWebSignature jws = getVerifiedJws(jwt);
        JwtClaims claims = JwtClaims.parse(jws.getPayload());

        Assert.assertEquals(4, claims.getClaimsMap().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);

        Assert.assertEquals("custom-value", claims.getClaimValue("customClaim"));
    }

    @Test
    public void testSignWithInvalidKeyLocation() throws Exception {
        JwtClaimsBuilder builder = Jwt.claims();

        JwtSignatureException thrown = assertThrows("JwtSignatureException is expected",
                JwtSignatureException.class, () -> builder.sign("/invalid-key-location.pem"));
        assertTrue(thrown.getCause()
                .getMessage().contains("Signing key can not be loaded from: /invalid-key-location.pem"));
    }

    @Test
    public void testSignClaimsAndHeaders() throws Exception {
        String jwt = Jwt.claims()
                .issuer("https://issuer.com")
                .jws()
                .header("customHeader", "custom-header-value")
                .keyId("key-id")
                .sign(getPrivateKey());

        JsonWebSignature jws = getVerifiedJws(jwt);
        JwtClaims claims = JwtClaims.parse(jws.getPayload());

        Assert.assertEquals(4, claims.getClaimsMap().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 4), claims);

        Assert.assertEquals("https://issuer.com", claims.getIssuer());
        Assert.assertEquals("key-id", jws.getKeyIdHeaderValue());
        Assert.assertEquals("custom-header-value", jws.getHeader("customHeader"));
    }

    private static PrivateKey getPrivateKey() throws Exception {
        return KeyUtils.readPrivateKey("/privateKey.pem");
    }

    private static PublicKey getEcPublicKey() throws Exception {
        return KeyUtils.readPublicKey("/ecPublicKey.pem", SignatureAlgorithm.ES256);
    }

    private static PublicKey getPublicKey() throws Exception {
        return KeyUtils.readPublicKey("/publicKey.pem");
    }

    private static JsonWebSignature getVerifiedJws(String jwt) throws Exception {
        return getVerifiedJws(jwt, getPublicKey());
    }

    static JsonWebSignature getVerifiedJws(String jwt, Key key) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setKey(key);
        jws.setCompactSerialization(jwt);
        Assert.assertTrue(jws.verifySignature());
        return jws;
    }

    private static void checkDefaultClaimsAndHeaders(Map<String, Object> headers, JwtClaims claims) throws Exception {
        checkDefaultClaimsAndHeaders(headers, claims, "RS256", 300);
    }

    static void checkDefaultClaimsAndHeaders(Map<String, Object> headers, JwtClaims claims, String algo,
            long expectedLifespan)
            throws Exception {
        NumericDate iat = claims.getIssuedAt();
        Assert.assertNotNull(iat);
        NumericDate exp = claims.getExpirationTime();
        Assert.assertNotNull(exp);
        long tokenLifespan = exp.getValue() - iat.getValue();
        Assert.assertTrue(tokenLifespan >= expectedLifespan && tokenLifespan <= expectedLifespan + 2);
        Assert.assertNotNull(claims.getJwtId());
        Assert.assertEquals(algo, headers.get("alg"));
        Assert.assertEquals("JWT", headers.get("typ"));
    }

    @Test
    public void testSignClaimsAllTypes() throws Exception {
        String jwt = Jwt.claims()
                .claim("stringClaim", "string")
                .claim("booleanClaim", true)
                .claim("numberClaim", 3)
                .claim("stringListClaim", Arrays.asList("1", "2"))
                .claim("numberListClaim", Arrays.asList(1, 2))
                .claim("mapClaim", Collections.singletonMap("key", "value"))
                .claim("jsonObjectClaim", Json.createObjectBuilder().add("jsonKey", "jsonValue").build())
                .claim("jsonArrayClaim", Json.createArrayBuilder().add(3).add(4).build())
                .sign(getPrivateKey());

        JsonWebSignature jws = getVerifiedJws(jwt);
        JwtClaims claims = JwtClaims.parse(jws.getPayload());

        Assert.assertEquals(11, claims.getClaimsMap().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);

        Assert.assertEquals("string", claims.getClaimValue("stringClaim"));
        Assert.assertTrue((Boolean) claims.getClaimValue("booleanClaim"));
        Assert.assertEquals(3L, claims.getClaimValue("numberClaim"));

        List<String> stringList = claims.getStringListClaimValue("stringListClaim");
        Assert.assertEquals(2, stringList.size());
        Assert.assertEquals("1", stringList.get(0));
        Assert.assertEquals("2", stringList.get(1));

        @SuppressWarnings("unchecked")
        List<Long> numberList = (List<Long>) claims.getClaimValue("numberListClaim");
        Assert.assertEquals(2, numberList.size());
        Assert.assertEquals(Long.valueOf(1), numberList.get(0));
        Assert.assertEquals(Long.valueOf(2), numberList.get(1));

        @SuppressWarnings("unchecked")
        Map<String, Object> mapClaim = (Map<String, Object>) claims.getClaimValue("mapClaim");
        Assert.assertEquals(1, mapClaim.size());
        Assert.assertEquals("value", mapClaim.get("key"));

        @SuppressWarnings("unchecked")
        Map<String, Object> mapJsonClaim = (Map<String, Object>) claims.getClaimValue("jsonObjectClaim");
        Assert.assertEquals(1, mapJsonClaim.size());
        Assert.assertEquals("jsonValue", mapJsonClaim.get("jsonKey"));

        @SuppressWarnings("unchecked")
        List<Long> numberJsonList = (List<Long>) claims.getClaimValue("jsonArrayClaim");
        Assert.assertEquals(2, numberJsonList.size());
        Assert.assertEquals(Long.valueOf(3), numberJsonList.get(0));
        Assert.assertEquals(Long.valueOf(4), numberJsonList.get(1));
    }

    @Test
    public void testSignExistingClaimsFromClassPath() throws Exception {
        doTestSignedExistingClaims(Jwt.claims("/token.json").sign());
    }

    @Test
    public void testSignExistingClaimsFromClassPathShortcut() throws Exception {
        doTestSignedExistingClaims(Jwt.sign("/token.json"));
    }

    @Test
    public void testSignExistingClaimsFromFileSystemWithFileScheme() throws Exception {
        URL resourceUrl = JwtSignTest.class.getResource("/token.json");
        Assert.assertEquals("file", resourceUrl.getProtocol());
        doTestSignedExistingClaims(Jwt.claims(resourceUrl.toString()).sign());
    }

    @Test
    public void testSignExistingClaimsFromFileSystemWithoutFileScheme() throws Exception {
        URL resourceUrl = JwtSignTest.class.getResource("/token.json");
        Assert.assertEquals("file", resourceUrl.getProtocol());
        doTestSignedExistingClaims(Jwt.claims(resourceUrl.toString().substring(5)).sign());
    }

    private void doTestSignedExistingClaims(String jwt) throws Exception {

        JsonWebSignature jws = getVerifiedJws(jwt);
        JwtClaims claims = JwtClaims.parse(jws.getPayload());

        Assert.assertEquals(9, claims.getClaimsMap().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims, "RS256", 1000);

        Assert.assertEquals("https://server.example.com", claims.getIssuer());
        Assert.assertEquals("a-123", claims.getClaimValue("jti"));
        Assert.assertEquals("24400320", claims.getSubject());
        Assert.assertEquals("jdoe@example.com", claims.getClaimValue("upn"));
        Assert.assertEquals("jdoe", claims.getClaimValue("preferred_username"));
        Assert.assertEquals("s6BhdRkqt3", claims.getAudience().get(0));
        Assert.assertEquals(1311281970L, claims.getExpirationTime().getValue());
        Assert.assertEquals(1311280970L, claims.getIssuedAt().getValue());
        Assert.assertEquals(1311280969, claims.getClaimValue("auth_time", Long.class).longValue());
    }

    @Test
    public void testSignClaimsEllipticCurve() throws Exception {
        EllipticCurveJsonWebKey jwk = createECJwk();

        String jwt = Jwt.claims()
                .claim("customClaim", "custom-value")
                .sign(jwk.getEcPrivateKey());

        JsonWebSignature jws = getVerifiedJws(jwt, jwk.getECPublicKey());
        JwtClaims claims = JwtClaims.parse(jws.getPayload());

        Assert.assertEquals(4, claims.getClaimsMap().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims, "ES256", 300);

        Assert.assertEquals("custom-value", claims.getClaimValue("customClaim"));
    }

    private static EllipticCurveJsonWebKey createECJwk() throws Exception {
        return EcJwkGenerator.generateJwk(EllipticCurves.P256);
    }

    @Test
    public void testSignClaimsSymmetricKey() throws Exception {
        SecretKey secretKey = createSecretKey();

        String jwt = Jwt.claims()
                .claim("customClaim", "custom-value")
                .sign(secretKey);

        JsonWebSignature jws = getVerifiedJws(jwt, secretKey);
        JwtClaims claims = JwtClaims.parse(jws.getPayload());

        Assert.assertEquals(4, claims.getClaimsMap().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims, "HS256", 300);

        Assert.assertEquals("custom-value", claims.getClaimValue("customClaim"));
    }

    @Test
    public void testSignClaimsWithSecret() throws Exception {
        String secret = "AyM1SysPpbyDfgZld3umj1qzKObwVMko";

        String jwt = Jwt.claims()
                .claim("customClaim", "custom-value")
                .signWithSecret(secret);

        SecretKey secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "AES");
        JsonWebSignature jws = getVerifiedJws(jwt, secretKey);
        JwtClaims claims = JwtClaims.parse(jws.getPayload());

        Assert.assertEquals(4, claims.getClaimsMap().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims, "HS256", 300);

        Assert.assertEquals("custom-value", claims.getClaimValue("customClaim"));
    }

    @Test
    public void testSignClaimsJwkSymmetricKey() throws Exception {
        JwtBuildConfigSource configSource = getConfigSource();
        configSource.setSigningKeyLocation("/privateKey.jwk");
        String jwt = null;
        try {
            jwt = Jwt.claims()
                    .claim("customClaim", "custom-value")
                    .jws()
                    .keyId("secretkey1")
                    .sign();
        } finally {
            configSource.setSigningKeyLocation("/privateKey.pem");
        }

        SecretKey secretKey = createSecretKey();
        JsonWebSignature jws = getVerifiedJws(jwt, secretKey);
        JwtClaims claims = JwtClaims.parse(jws.getPayload());

        Assert.assertEquals(4, claims.getClaimsMap().size());
        Map<String, Object> headers = getJwsHeaders(jwt, 3);
        checkDefaultClaimsAndHeaders(headers, claims, "HS256", 300);
        Assert.assertEquals("secretkey1", headers.get("kid"));
        Assert.assertEquals("custom-value", claims.getClaimValue("customClaim"));
    }

    @Test
    public void testSignClaimsEcKey() throws Exception {
        JwtBuildConfigSource configSource = getConfigSource();
        configSource.setSigningKeyLocation("/ecPrivateKey.pem");
        String jwt = null;
        try {
            jwt = Jwt.claims()
                    .claim("customClaim", "custom-value")
                    .jws()
                    .algorithm(SignatureAlgorithm.ES256)
                    .keyId("eckey1")
                    .sign();
        } finally {
            configSource.setSigningKeyLocation("/privateKey.pem");
        }

        PublicKey ecKey = getEcPublicKey();
        JsonWebSignature jws = getVerifiedJws(jwt, ecKey);
        JwtClaims claims = JwtClaims.parse(jws.getPayload());

        Assert.assertEquals(4, claims.getClaimsMap().size());
        Map<String, Object> headers = getJwsHeaders(jwt, 3);
        checkDefaultClaimsAndHeaders(headers, claims, "ES256", 300);
        Assert.assertEquals("eckey1", headers.get("kid"));
        Assert.assertEquals("custom-value", claims.getClaimValue("customClaim"));
    }

    private static SecretKey createSecretKey() throws Exception {
        String jwkJson = "{\"kty\":\"oct\",\"k\":\"Fdh9u8rINxfivbrianbbVT1u232VQBZYKx1HGAGPt2I\"}";
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(jwkJson);
        return (SecretKey) jwk.getKey();
    }

    @Test
    public void testWrongKeyForRSAAlgorithm() throws Exception {
        // EC
        try {
            Jwt.claims()
                    .claim("customClaim", "custom-value")
                    .jws()
                    .header("alg", "RS256")
                    .sign(createECJwk().getEcPrivateKey());
            Assert.fail("EC key can not be used with RS256");
        } catch (JwtException ex) {
            // expected
        }
        // HS
        try {
            Jwt.claims()
                    .claim("customClaim", "custom-value")
                    .jws()
                    .header("alg", "RS256")
                    .sign(createSecretKey());
            Assert.fail("HS key can not be used with RS256");
        } catch (JwtException ex) {
            // expected
        }
    }

    static Map<String, Object> getJwsHeaders(String compactJws, int expectedSize) throws Exception {
        int firstDot = compactJws.indexOf(".");
        String headersJson = new Base64Url().base64UrlDecodeToUtf8String(compactJws.substring(0, firstDot));
        Map<String, Object> headers = JsonUtil.parseJson(headersJson);
        Assert.assertEquals(expectedSize, headers.size());
        return headers;
    }

    static JwtBuildConfigSource getConfigSource() {
        for (ConfigSource cs : ConfigProvider.getConfig().getConfigSources()) {
            if (cs instanceof JwtBuildConfigSource) {
                return (JwtBuildConfigSource) cs;
            }
        }
        return null;
    }

    static class TestJsonWebToken implements JsonWebToken {

        private JwtClaims claims;

        TestJsonWebToken(JwtClaims claims) {
            this.claims = claims;
        }

        @Override
        public String getName() {
            return null;
        }

        @Override
        public Set<String> getClaimNames() {
            return new HashSet<>(claims.getClaimNames());
        }

        @SuppressWarnings("unchecked")
        @Override
        public <T> T getClaim(String claimName) {
            if (Claims.aud.name().equals(claimName)) {
                try {
                    return (T) new HashSet<>(claims.getAudience());
                } catch (MalformedClaimException ex) {
                    throw new RuntimeException(ex);
                }
            }
            return (T) claims.getClaimValue(claimName);
        }

    }

}
