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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import jakarta.json.Json;
import jakarta.json.JsonObject;

import org.eclipse.microprofile.config.ConfigProvider;
import org.eclipse.microprofile.config.spi.ConfigSource;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jose4j.base64url.Base64Url;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtSignatureException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.EdDsaKeyUtil;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.UnresolvableKeyException;
import org.junit.jupiter.api.Test;

import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.util.KeyUtils;
import io.smallrye.jwt.util.ResourceUtils;

class JwtSignTest {
    @Test
    void signClaims() throws Exception {
        signAndVerifyClaims();
    }

    @Test
    void signClaimsCustomExpAndIssuerAndAud() throws Exception {
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
    void enhanceAndResignToken() throws Exception {
        JsonWebToken token = new TestJsonWebToken(signAndVerifyClaims());

        String jwt = Jwt.claims(token).claim("newClaim", "new-value").sign();

        // verify
        JsonWebSignature jws = getVerifiedJws(jwt);
        JwtClaims claims = JwtClaims.parse(jws.getPayload());
        assertEquals(7, claims.getClaimsMap().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);
        assertEquals("custom-value", claims.getClaimValue("customClaim"));

        assertEquals("new-value", claims.getClaimValue("newClaim"));
        assertEquals("https://default-issuer", claims.getIssuer());
        assertEquals(1, claims.getAudience().size());
        assertEquals("https://localhost:8081", claims.getAudience().get(0));
    }

    @Test
    void enhanceAndResignTokenWithCustomClaimRemoved() throws Exception {
        JwtClaims tokenClaims = signAndVerifyClaims();
        assertEquals("custom-value", tokenClaims.getClaimValue("customClaim"));
        JsonWebToken token = new TestJsonWebToken(tokenClaims);

        String jwt = Jwt.claims(token).remove("customClaim")
                // this just checks trying to remove non-existent claims does not cause some NPE
                .remove(UUID.randomUUID().toString())
                .claim("newClaim", "new-value").sign();

        // verify
        JsonWebSignature jws = getVerifiedJws(jwt);
        JwtClaims claims = JwtClaims.parse(jws.getPayload());
        assertEquals(6, claims.getClaimsMap().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);
        assertNull(claims.getClaimValue("customClaim"));

        assertEquals("new-value", claims.getClaimValue("newClaim"));
        assertEquals("https://default-issuer", claims.getIssuer());
        assertEquals(1, claims.getAudience().size());
        assertEquals("https://localhost:8081", claims.getAudience().get(0));
    }

    @Test
    void enhanceAndResignTokenWithConfiguredIssuerAndAudUsed() throws Exception {
        JsonWebToken token = new TestJsonWebToken(signAndVerifyClaims());

        assertEquals("https://default-issuer", token.getIssuer());
        assertEquals(1, token.getAudience().size());
        assertEquals("https://localhost:8081", token.getAudience().iterator().next());

        JwtBuildConfigSource configSource = getConfigSource();
        configSource.setIssuerPropertyRequired(true);
        configSource.setAudiencePropertyRequired(true);
        configSource.setOverrideMatchingClaims(true);

        try {
            String jwt = Jwt.claims(token).claim("newClaim", "new-value").sign();

            // verify
            JsonWebSignature jws = getVerifiedJws(jwt);
            JwtClaims claims = JwtClaims.parse(jws.getPayload());
            assertEquals(7, claims.getClaimsMap().size());
            checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);
            assertEquals("custom-value", claims.getClaimValue("customClaim"));

            assertEquals("new-value", claims.getClaimValue("newClaim"));
            assertEquals("https://custom-issuer", claims.getIssuer());
            assertEquals(1, claims.getAudience().size());
            assertEquals("https://custom-audience", claims.getAudience().get(0));
        } finally {
            configSource.setIssuerPropertyRequired(false);
            configSource.setAudiencePropertyRequired(false);
            configSource.setOverrideMatchingClaims(false);
        }
    }

    private JwtClaims signAndVerifyClaims() throws Exception {
        return signAndVerifyClaims(null, null, null);
    }

    private JwtClaims signAndVerifyClaims(Long customLifespan, String issuer, String aud) throws Exception {
        JwtClaimsBuilder builder = Jwt.claims().claim("customClaim", "custom-value");
        if (issuer == null) {
            builder.issuer("https://default-issuer");
        }
        if (aud == null) {
            builder.audience("https://localhost:8081");
        }
        String jwt = builder.sign(getPrivateKey());
        JsonWebSignature jws = getVerifiedJws(jwt);
        JwtClaims claims = JwtClaims.parse(jws.getPayload());
        assertEquals(6, claims.getClaimsMap().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims, "RS256", customLifespan != null ? customLifespan : 300);

        assertEquals("custom-value", claims.getClaimValue("customClaim"));
        assertEquals((issuer == null ? "https://default-issuer" : issuer), claims.getIssuer());
        List<String> audiences = claims.getAudience();
        assertEquals(1, audiences.size());
        assertEquals((aud == null ? "https://localhost:8081" : aud), audiences.get(0));
        return claims;
    }

    @Test
    void customIssuedAtExpiresAtLong() throws Exception {
        Instant now = Instant.now();
        String jwt = Jwt.claims().issuedAt(now).expiresAt(now.getEpochSecond() + 3000).sign();
        verifyJwtCustomIssuedAtExpiresAt(now, jwt);
    }

    @Test
    void customIssuedAtExpiresAtInstant() throws Exception {
        Instant now = Instant.now();
        String jwt = Jwt.claims().issuedAt(now).expiresAt(now.plusSeconds(3000)).sign();
        verifyJwtCustomIssuedAtExpiresAt(now, jwt);
    }

    @Test
    void customIssuedAtExpiresInLong() throws Exception {
        Instant now = Instant.now();
        String jwt = Jwt.claims().issuedAt(now).expiresIn(3000).sign();
        verifyJwtCustomIssuedAtExpiresAt(now, jwt);
    }

    @Test
    void customIssuedAtExpiresInDuration() throws Exception {
        Instant now = Instant.now();
        String jwt = Jwt.claims().issuedAt(now).expiresIn(Duration.ofSeconds(3000)).sign();
        verifyJwtCustomIssuedAtExpiresAt(now, jwt);
    }

    private void verifyJwtCustomIssuedAtExpiresAt(Instant now, String jwt) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setKey(KeyUtils.readPublicKey("/publicKey.pem"));
        jws.setCompactSerialization(jwt);
        assertTrue(jws.verifySignature());
        JwtClaims claims = JwtClaims.parse(jws.getPayload());
        assertEquals(3, claims.getClaimsMap().size());
        assertEquals(now.getEpochSecond(), claims.getIssuedAt().getValue());
        assertEquals(now.getEpochSecond() + 3000, claims.getExpirationTime().getValue());
        assertNotNull(claims.getJwtId());
    }

    @Test
    void signMapOfClaims() throws Exception {
        String jwt = Jwt.claims(Collections.singletonMap("customClaim", "custom-value"))
                .sign(getPrivateKey());

        JsonWebSignature jws = getVerifiedJws(jwt);
        JwtClaims claims = JwtClaims.parse(jws.getPayload());

        assertEquals(4, claims.getClaimsMap().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);

        assertEquals("custom-value", claims.getClaimValue("customClaim"));
    }

    @Test
    void signMapOfClaimsShortcut() throws Exception {
        String jwt = Jwt.sign(Collections.singletonMap("customClaim", "custom-value"));

        JsonWebSignature jws = getVerifiedJws(jwt);
        JwtClaims claims = JwtClaims.parse(jws.getPayload());

        assertEquals(4, claims.getClaimsMap().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);

        assertEquals("custom-value", claims.getClaimValue("customClaim"));
    }

    @Test
    void signMapOfClaimsWithKeyLocation() throws Exception {
        String jwt = Jwt.claims(Collections.singletonMap("customClaim", "custom-value"))
                .sign("/privateKey.pem");

        JsonWebSignature jws = getVerifiedJws(jwt);
        JwtClaims claims = JwtClaims.parse(jws.getPayload());

        assertEquals(4, claims.getClaimsMap().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);

        assertEquals("custom-value", claims.getClaimValue("customClaim"));
    }

    @Test
    void signJsonObject() throws Exception {
        JsonObject userName = Json.createObjectBuilder().add("username", "Alice").build();
        JsonObject userAddress = Json.createObjectBuilder().add("city", "someCity").add("street", "someStreet").build();
        JsonObject json = Json.createObjectBuilder(userName).add("address", userAddress).build();

        String jwt = Jwt.claims(json).sign("/privateKey.pem");

        verifySignedJsonObject(jwt);
    }

    @Test
    void signJsonObjectShortcut() throws Exception {
        JsonObject userName = Json.createObjectBuilder().add("username", "Alice").build();
        JsonObject userAddress = Json.createObjectBuilder().add("city", "someCity").add("street", "someStreet").build();
        JsonObject json = Json.createObjectBuilder(userName).add("address", userAddress).build();

        String jwt = Jwt.sign(json);

        verifySignedJsonObject(jwt);
    }

    private void verifySignedJsonObject(String jwt) throws Exception {
        JsonWebSignature jws = getVerifiedJws(jwt);
        JwtClaims claims = JwtClaims.parse(jws.getPayload());

        assertEquals(5, claims.getClaimsMap().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);

        assertEquals("Alice", claims.getClaimValue("username"));
        @SuppressWarnings("unchecked")
        Map<String, String> address = (Map<String, String>) claims.getClaimValue("address");
        assertEquals(2, address.size());
        assertEquals("someCity", address.get("city"));
        assertEquals("someStreet", address.get("street"));
    }

    @Test
    void signWithShortRSAKey() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair(1024);
        try {
            Jwt.claims().sign(keyPair.getPrivate());
            fail("JwtSignatureException is expected due to the invalid key size");
        } catch (JwtSignatureException ex) {
            assertEquals(
                    "SRJWT05012: Failure to create a signed JWT token: An RSA key of size 2048 bits or larger MUST be used with the all JOSE RSA algorithms (given key was only 1024 bits).",
                    ex.getMessage());
        }
    }

    @Test
    void signWithShortRSAKeyAndRelaxedValidation() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair(1024);

        JwtBuildConfigSource configSource = getConfigSource();
        configSource.setRelaxSignatureKeyValidation(true);
        try {
            String jwt = Jwt.claims(Collections.singletonMap("customClaim", "custom-value"))
                    .sign(keyPair.getPrivate());

            JsonWebSignature jws = getVerifiedJws(jwt, keyPair.getPublic(), true);
            JwtClaims claims = JwtClaims.parse(jws.getPayload());

            assertEquals(4, claims.getClaimsMap().size());
            checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);

            assertEquals("custom-value", claims.getClaimValue("customClaim"));
        } finally {
            configSource.setRelaxSignatureKeyValidation(false);
        }
    }

    @Test
    void signClaimsConfiguredKeyLocation() throws Exception {
        JwtBuildConfigSource configSource = getConfigSource();
        try {
            configSource.resetSigningKeyCallCount();
            JwtClaimsBuilder builder = Jwt.claims().claim("customClaim", "custom-value");
            String jti1 = doTestSignClaimsConfiguredKey(builder);
            assertNotNull(jti1);
            String jti2 = doTestSignClaimsConfiguredKey(builder);
            assertNotNull(jti2);
            assertNotEquals(jti1, jti2);
            assertEquals(1, configSource.getSigningKeyCallCount());
        } finally {
            configSource.resetSigningKeyCallCount();
        }
    }

    @Test
    void signClaimsConfiguredKeyContent() throws Exception {
        JwtBuildConfigSource configSource = getConfigSource();
        try {
            configSource.resetSigningKeyCallCount();
            configSource.setUseSignKeyProperty(true);
            JwtClaimsBuilder builder = Jwt.claims().claim("customClaim", "custom-value");
            String jti1 = doTestSignClaimsConfiguredKey(builder);
            assertNotNull(jti1);
            String jti2 = doTestSignClaimsConfiguredKey(builder);
            assertNotNull(jti2);
            assertNotEquals(jti1, jti2);
            assertEquals(1, configSource.getSigningKeyCallCount());
        } finally {
            configSource.resetSigningKeyCallCount();
            configSource.setUseSignKeyProperty(false);
        }
    }

    private String doTestSignClaimsConfiguredKey(JwtClaimsBuilder builder) throws Exception {
        String jwt = builder.sign();

        JsonWebSignature jws = getVerifiedJws(jwt);
        JwtClaims claims = JwtClaims.parse(jws.getPayload());

        assertEquals(4, claims.getClaimsMap().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);

        assertEquals("custom-value", claims.getClaimValue("customClaim"));
        return claims.getJwtId();
    }

    @Test
    void signWithInvalidKeyLocation() throws Exception {
        JwtClaimsBuilder builder = Jwt.claims();

        JwtSignatureException thrown = assertThrows(JwtSignatureException.class,
                () -> builder.sign("/invalid-key-location.pem"), "JwtSignatureException is expected");
        assertTrue(thrown.getCause()
                .getMessage().contains("Signing key can not be loaded from: /invalid-key-location.pem"));
    }

    @Test
    void signClaimsAndHeaders() throws Exception {
        String jwt = Jwt.claims()
                .issuer("https://issuer.com")
                .jws()
                .header("customHeader", "custom-header-value")
                .keyId("key-id")
                .sign(getPrivateKey());

        JsonWebSignature jws = getVerifiedJws(jwt);
        JwtClaims claims = JwtClaims.parse(jws.getPayload());

        assertEquals(4, claims.getClaimsMap().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 4), claims);

        assertEquals("https://issuer.com", claims.getIssuer());
        assertEquals("key-id", jws.getKeyIdHeaderValue());
        assertEquals("custom-header-value", jws.getHeader("customHeader"));
    }

    private static PrivateKey getPrivateKey() throws Exception {
        return KeyUtils.readPrivateKey("/privateKey.pem");
    }

    private static PrivateKey getEdEcPrivateKey() throws Exception {
        return (PrivateKey) KeyUtils.readSigningKey("/edEcPrivateKey.jwk", null, null);
    }

    private static PublicKey getEdEcPublicKey() throws Exception {
        String keyContent = KeyUtils.readKeyContent("/edEcPublicKey.jwk");
        return PublicJsonWebKey.Factory.newPublicJwk(keyContent).getPublicKey();
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
        return getVerifiedJws(jwt, key, false);
    }

    static JsonWebSignature getVerifiedJws(String jwt, Key key, boolean relaxKeyValidation) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setKey(key);
        jws.setCompactSerialization(jwt);
        if (relaxKeyValidation) {
            jws.setDoKeyValidation(false);
        }
        assertTrue(jws.verifySignature());
        return jws;
    }

    private static void checkDefaultClaimsAndHeaders(Map<String, Object> headers, JwtClaims claims) throws Exception {
        checkDefaultClaimsAndHeaders(headers, claims, "RS256", 300);
    }

    static void checkDefaultClaimsAndHeaders(Map<String, Object> headers, JwtClaims claims, String algo,
            long expectedLifespan)
            throws Exception {
        NumericDate iat = claims.getIssuedAt();
        assertNotNull(iat);
        NumericDate exp = claims.getExpirationTime();
        assertNotNull(exp);
        long tokenLifespan = exp.getValue() - iat.getValue();
        assertTrue(tokenLifespan >= expectedLifespan && tokenLifespan <= expectedLifespan + 2);
        assertNotNull(claims.getJwtId());
        assertEquals(algo, headers.get("alg"));
        assertEquals("JWT", headers.get("typ"));
    }

    @Test
    void signClaimsAllTypes() throws Exception {
        String jwt = Jwt.claims()
                .scope(Set.of("read:data", "write:data"))
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

        assertEquals(12, claims.getClaimsMap().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);

        String scope = claims.getStringClaimValue("scope");
        assertTrue("read:data write:data".equals(scope) || "write:data read:data".equals(scope));

        assertEquals("string", claims.getClaimValue("stringClaim"));
        assertTrue((Boolean) claims.getClaimValue("booleanClaim"));
        assertEquals(3L, claims.getClaimValue("numberClaim"));

        List<String> stringList = claims.getStringListClaimValue("stringListClaim");
        assertEquals(2, stringList.size());
        assertEquals("1", stringList.get(0));
        assertEquals("2", stringList.get(1));

        @SuppressWarnings("unchecked")
        List<Long> numberList = (List<Long>) claims.getClaimValue("numberListClaim");
        assertEquals(2, numberList.size());
        assertEquals(Long.valueOf(1), numberList.get(0));
        assertEquals(Long.valueOf(2), numberList.get(1));

        @SuppressWarnings("unchecked")
        Map<String, Object> mapClaim = (Map<String, Object>) claims.getClaimValue("mapClaim");
        assertEquals(1, mapClaim.size());
        assertEquals("value", mapClaim.get("key"));

        @SuppressWarnings("unchecked")
        Map<String, Object> mapJsonClaim = (Map<String, Object>) claims.getClaimValue("jsonObjectClaim");
        assertEquals(1, mapJsonClaim.size());
        assertEquals("jsonValue", mapJsonClaim.get("jsonKey"));

        @SuppressWarnings("unchecked")
        List<Long> numberJsonList = (List<Long>) claims.getClaimValue("jsonArrayClaim");
        assertEquals(2, numberJsonList.size());
        assertEquals(Long.valueOf(3), numberJsonList.get(0));
        assertEquals(Long.valueOf(4), numberJsonList.get(1));
    }

    @Test
    void signExistingClaimsFromClassPath() throws Exception {
        doTestSignedExistingClaims(Jwt.claims("/token.json").sign());
    }

    @Test
    void signExistingClaimsFromClassPathShortcut() throws Exception {
        doTestSignedExistingClaims(Jwt.sign("/token.json"));
    }

    @Test
    void signExistingClaimsFromFileSystemWithFileScheme() throws Exception {
        URL resourceUrl = JwtSignTest.class.getResource("/token.json");
        assertEquals("file", resourceUrl.getProtocol());
        doTestSignedExistingClaims(Jwt.claims(resourceUrl.toString()).sign());
    }

    @Test
    void signExistingClaimsFromFileSystemWithoutFileScheme() throws Exception {
        URL resourceUrl = JwtSignTest.class.getResource("/token.json");
        assertEquals("file", resourceUrl.getProtocol());
        doTestSignedExistingClaims(Jwt.claims(resourceUrl.toString().substring(5)).sign());
    }

    private void doTestSignedExistingClaims(String jwt) throws Exception {

        JsonWebSignature jws = getVerifiedJws(jwt);
        JwtClaims claims = JwtClaims.parse(jws.getPayload());

        assertEquals(9, claims.getClaimsMap().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims, "RS256", 1000);

        assertEquals("https://server.example.com", claims.getIssuer());
        assertEquals("a-123", claims.getClaimValue("jti"));
        assertEquals("24400320", claims.getSubject());
        assertEquals("jdoe@example.com", claims.getClaimValue("upn"));
        assertEquals("jdoe", claims.getClaimValue("preferred_username"));
        assertEquals("s6BhdRkqt3", claims.getAudience().get(0));
        assertEquals(1311281970L, claims.getExpirationTime().getValue());
        assertEquals(1311280970L, claims.getIssuedAt().getValue());
        assertEquals(1311280969, claims.getClaimValue("auth_time", Long.class).longValue());
    }

    @Test
    void signClaimsEllipticCurve() throws Exception {
        EllipticCurveJsonWebKey ecJwk = createECJwk();

        String jwt = Jwt.claims()
                .claim("customClaim", "custom-value")
                .claim("evidence", ecJwk.getECPublicKey())
                .jws().jwk(ecJwk.getECPublicKey())
                .sign(ecJwk.getEcPrivateKey());

        JsonWebSignature jws = getVerifiedJws(jwt, ecJwk.getECPublicKey());
        JwtClaims claims = JwtClaims.parse(jws.getPayload());
        assertEquals(5, claims.getClaimsMap().size());

        Map<String, Object> headers = getJwsHeaders(jwt, 3);
        checkDefaultClaimsAndHeaders(headers, claims, "ES256", 300);

        assertEquals("custom-value", claims.getClaimValue("customClaim"));

        @SuppressWarnings("unchecked")
        Map<String, Object> jwk = (Map<String, Object>) headers.get("jwk");
        assertEquals(4, jwk.size());
        assertEquals("EC", jwk.get("kty"));
        assertEquals("P-256", jwk.get("crv"));
        assertNotNull(jwk.get("x"));
        assertNotNull(jwk.get("y"));

        @SuppressWarnings("unchecked")
        Map<String, Object> evidence = (Map<String, Object>) claims.getClaimValue("evidence");
        assertEquals(evidence, jwk);
    }

    @Test
    void signClaimsEd25519() throws Exception {
        if (Runtime.version().version().get(0) >= 17) {
            EdDsaKeyUtil keyUtil = new EdDsaKeyUtil();
            KeyPair keyPairEd25519 = keyUtil.generateKeyPair(EdDsaKeyUtil.ED25519);
            KeyPair keyPairEd448 = keyUtil.generateKeyPair(EdDsaKeyUtil.ED448);

            String jwt = Jwt.claims()
                    .claim("customClaim", "custom-value")
                    .jws().jwk(keyPairEd25519.getPublic())
                    .sign(keyPairEd25519.getPrivate());

            JsonWebSignature jws = getVerifiedJws(jwt, keyPairEd25519.getPublic());
            JwtClaims claims = JwtClaims.parse(jws.getPayload());

            assertEquals(4, claims.getClaimsMap().size());
            Map<String, Object> headers = getJwsHeaders(jwt, 3);
            checkDefaultClaimsAndHeaders(headers, claims, "EdDSA", 300);

            assertEquals("custom-value", claims.getClaimValue("customClaim"));

            @SuppressWarnings("unchecked")
            Map<String, Object> jwk = (Map<String, Object>) headers.get("jwk");
            assertEquals(3, jwk.size());
            assertEquals("OKP", jwk.get("kty"));
            assertEquals("Ed25519", jwk.get("crv"));
            assertNotNull(jwk.get("x"));

            JwtConsumerBuilder builder = new JwtConsumerBuilder();
            builder.setVerificationKey(keyPairEd448.getPublic());
            builder.setJwsAlgorithmConstraints(
                    new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, "EdDSA"));
            try {
                builder.build().process(jwt);
                fail("ED25519 curve was used to sign the token, must not be verified with ED448");
            } catch (InvalidJwtSignatureException ex) {

            }
        }
    }

    @Test
    void signClaimsEd25519WithJwk() throws Exception {
        if (Runtime.version().version().get(0) >= 17) {
            EdDsaKeyUtil keyUtil = new EdDsaKeyUtil();
            KeyPair keyPairEd448 = keyUtil.generateKeyPair(EdDsaKeyUtil.ED448);

            String jwt = Jwt.claims()
                    .claim("customClaim", "custom-value")
                    .sign(getEdEcPrivateKey());

            JsonWebSignature jws = getVerifiedJws(jwt, getEdEcPublicKey());
            JwtClaims claims = JwtClaims.parse(jws.getPayload());

            assertEquals(4, claims.getClaimsMap().size());
            Map<String, Object> headers = getJwsHeaders(jwt, 2);
            checkDefaultClaimsAndHeaders(headers, claims, "EdDSA", 300);

            assertEquals("custom-value", claims.getClaimValue("customClaim"));

            JwtConsumerBuilder builder = new JwtConsumerBuilder();
            builder.setVerificationKey(keyPairEd448.getPublic());
            builder.setJwsAlgorithmConstraints(
                    new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, "EdDSA"));
            try {
                builder.build().process(jwt);
                fail("ED25519 curve was used to sign the token, must not be verified with ED448");
            } catch (InvalidJwtSignatureException ex) {

            }
        }
    }

    @Test
    void signClaimsEd448() throws Exception {
        if (Runtime.version().version().get(0) >= 17) {
            EdDsaKeyUtil keyUtil = new EdDsaKeyUtil();
            KeyPair keyPairEd25519 = keyUtil.generateKeyPair(EdDsaKeyUtil.ED25519);
            KeyPair keyPairEd448 = keyUtil.generateKeyPair(EdDsaKeyUtil.ED448);

            String jwt = Jwt.claims()
                    .claim("customClaim", "custom-value")
                    .sign(keyPairEd448.getPrivate());

            JsonWebSignature jws = getVerifiedJws(jwt, keyPairEd448.getPublic());
            JwtClaims claims = JwtClaims.parse(jws.getPayload());

            assertEquals(4, claims.getClaimsMap().size());
            Map<String, Object> headers = getJwsHeaders(jwt, 2);
            checkDefaultClaimsAndHeaders(headers, claims, "EdDSA", 300);

            assertEquals("custom-value", claims.getClaimValue("customClaim"));

            JwtConsumerBuilder builder = new JwtConsumerBuilder();
            builder.setVerificationKey(keyPairEd25519.getPublic());
            builder.setJwsAlgorithmConstraints(
                    new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, "EdDSA"));
            try {
                builder.build().process(jwt);
                fail("ED448 curve was used to sign the token, must not be verified with ED25519");
            } catch (InvalidJwtSignatureException ex) {

            }
        }
    }

    private static EllipticCurveJsonWebKey createECJwk() throws Exception {
        return EcJwkGenerator.generateJwk(EllipticCurves.P256);
    }

    @Test
    void signClaimsSymmetricKey() throws Exception {
        SecretKey secretKey = createSecretKey();

        String jwt = Jwt.claims()
                .claim("customClaim", "custom-value")
                .sign(secretKey);

        JsonWebSignature jws = getVerifiedJws(jwt, secretKey);
        JwtClaims claims = JwtClaims.parse(jws.getPayload());

        assertEquals(4, claims.getClaimsMap().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims, "HS256", 300);

        assertEquals("custom-value", claims.getClaimValue("customClaim"));
    }

    @Test
    void signWithKeyStore() throws Exception {
        JwtBuildConfigSource configSource = getConfigSource();
        configSource.setUseKeyStore(true);
        configSource.setSigningKeyLocation("/keystore.p12");
        try {
            KeyStore keyStore = KeyUtils.loadKeyStore("keystore.p12", "password", Optional.of("PKCS12"), Optional.empty());
            PublicKey verificationKey = keyStore.getCertificate("server").getPublicKey();

            String jwt = Jwt.claims()
                    .claim("customClaim", "custom-value")
                    .jws().jwk(verificationKey)
                    .sign();

            JsonWebSignature jws = getVerifiedJws(jwt, verificationKey);
            JwtClaims claims = JwtClaims.parse(jws.getPayload());

            assertEquals(4, claims.getClaimsMap().size());
            Map<String, Object> headers = getJwsHeaders(jwt, 3);
            checkDefaultClaimsAndHeaders(headers, claims, "RS256", 300);
            assertEquals("custom-value", claims.getClaimValue("customClaim"));

            @SuppressWarnings("unchecked")
            Map<String, Object> jwk = (Map<String, Object>) headers.get("jwk");
            assertEquals(3, jwk.size());
            assertEquals("RSA", jwk.get("kty"));
            assertNotNull(jwk.get("n"));
            assertNotNull(jwk.get("e"));
        } finally {
            configSource.setUseKeyStore(false);
            configSource.setSigningKeyLocation("/privateKey.pem");
        }
    }

    @Test
    void signClaimsWithSecret() throws Exception {
        String secret = "AyM1SysPpbyDfgZld3umj1qzKObwVMko";

        String jwt = Jwt.claims()
                .claim("customClaim", "custom-value")
                .signWithSecret(secret);

        SecretKey secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "AES");
        JsonWebSignature jws = getVerifiedJws(jwt, secretKey);
        JwtClaims claims = JwtClaims.parse(jws.getPayload());

        assertEquals(4, claims.getClaimsMap().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims, "HS256", 300);

        assertEquals("custom-value", claims.getClaimValue("customClaim"));
    }

    @Test
    void signClaimsWithShortSecret() throws Exception {
        String secret = "AyM1SysPpbyDfgZld3umj1qzKObw";

        JwtSignatureException thrown = assertThrows(JwtSignatureException.class,
                () -> Jwt.claims().claim("customClaim", "custom-value").signWithSecret(secret),
                "JwtSignatureException is expected");
        assertEquals(
                "A key of the same size as the hash output (i.e. 256 bits for HS256) or larger MUST be used with the HMAC SHA"
                        + " algorithms but this key is only 224 bits",
                thrown.getCause().getMessage());
    }

    @Test
    void signClaimsWithShortSecretAndRelaxedValidation() throws Exception {
        String secret = "AyM1SysPpbyDfgZld3umj1qzKObw";

        JwtBuildConfigSource configSource = getConfigSource();
        configSource.setRelaxSignatureKeyValidation(true);
        try {
            String jwt = Jwt.claims()
                    .claim("customClaim", "custom-value")
                    .signWithSecret(secret);

            SecretKey secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "AES");
            JsonWebSignature jws = getVerifiedJws(jwt, secretKey, true);
            JwtClaims claims = JwtClaims.parse(jws.getPayload());

            assertEquals(4, claims.getClaimsMap().size());
            checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims, "HS256", 300);

            assertEquals("custom-value", claims.getClaimValue("customClaim"));
        } finally {
            configSource.setRelaxSignatureKeyValidation(false);
        }
    }

    @Test
    void signClaimsJwkSymmetricKey() throws Exception {
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

        assertEquals(4, claims.getClaimsMap().size());
        Map<String, Object> headers = getJwsHeaders(jwt, 3);
        checkDefaultClaimsAndHeaders(headers, claims, "HS256", 300);
        assertEquals("secretkey1", headers.get("kid"));
        assertEquals("custom-value", claims.getClaimValue("customClaim"));
    }

    @Test
    void signClaimsEcKey() throws Exception {
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

        assertEquals(4, claims.getClaimsMap().size());
        Map<String, Object> headers = getJwsHeaders(jwt, 3);
        checkDefaultClaimsAndHeaders(headers, claims, "ES256", 300);
        assertEquals("eckey1", headers.get("kid"));
        assertEquals("custom-value", claims.getClaimValue("customClaim"));
    }

    private static SecretKey createSecretKey() throws Exception {
        String jwkJson = "{\"kty\":\"oct\",\"k\":\"Fdh9u8rINxfivbrianbbVT1u232VQBZYKx1HGAGPt2I\"}";
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(jwkJson);
        return (SecretKey) jwk.getKey();
    }

    @Test
    void wrongKeyForRSAAlgorithm() throws Exception {
        // EC
        try {
            Jwt.claims()
                    .claim("customClaim", "custom-value")
                    .jws()
                    .header("alg", "RS256")
                    .sign(createECJwk().getEcPrivateKey());
            fail("EC key can not be used with RS256");
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
            fail("HS key can not be used with RS256");
        } catch (JwtException ex) {
            // expected
        }
    }

    @Test
    void testCertificateChainHeader() throws Exception {
        X509Certificate cert = KeyUtils.getCertificate(ResourceUtils.readResource("/certificate.pem"));
        String jwtString = Jwt.upn("Alice")
                .jws().chain(cert)
                .sign("/privateKey2.pem");

        JwtConsumerBuilder builder = new JwtConsumerBuilder();
        builder.setVerificationKeyResolver(new VerificationKeyResolver() {

            @Override
            public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext)
                    throws UnresolvableKeyException {
                try {
                    return jws.getCertificateChainHeaderValue().get(0).getPublicKey();
                } catch (JoseException ex) {
                    throw new UnresolvableKeyException("Invalid chain", ex);
                }
            }
        });
        builder.setJwsAlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, "RS256");
        JwtClaims jwt = builder.build().process(jwtString).getJwtClaims();

        assertEquals("Alice", jwt.getClaimValueAsString("upn"));
    }

    @Test
    void testInvalidCertificateChainHeader() throws Exception {
        X509Certificate cert = KeyUtils.getCertificate(ResourceUtils.readResource("/certificate.pem"));
        String jwtString = Jwt.upn("Alice")
                .jws().chain(cert)
                // this key does not correspond to the public key in the loaded certificate
                .sign("/privateKey.pem");

        JwtConsumerBuilder builder = new JwtConsumerBuilder();
        builder.setVerificationKeyResolver(new VerificationKeyResolver() {

            @Override
            public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext)
                    throws UnresolvableKeyException {
                try {
                    return jws.getCertificateChainHeaderValue().get(0).getPublicKey();
                } catch (JoseException ex) {
                    throw new UnresolvableKeyException("Invalid chain", ex);
                }
            }
        });
        builder.setJwsAlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, "RS256");
        JwtConsumer consumer = builder.build();
        assertThrows(InvalidJwtSignatureException.class, () -> consumer.process(jwtString));
    }

    static Map<String, Object> getJwsHeaders(String compactJws, int expectedSize) throws Exception {
        int firstDot = compactJws.indexOf(".");
        String headersJson = new Base64Url().base64UrlDecodeToUtf8String(compactJws.substring(0, firstDot));
        Map<String, Object> headers = JsonUtil.parseJson(headersJson);
        assertEquals(expectedSize, headers.size());
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
