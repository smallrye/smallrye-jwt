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
import static org.junit.jupiter.api.Assertions.assertFalse;
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
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.JRE;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.smallrye.jwt.algorithm.EdDSAVerifier;
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
        SignedJWT signedJWT = getVerifiedJws(jwt);
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
        assertEquals(7, claims.getClaims().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);
        assertEquals("custom-value", claims.getClaim("customClaim"));

        assertEquals("new-value", claims.getClaim("newClaim"));
        assertEquals("https://default-issuer", claims.getIssuer());
        assertEquals(1, claims.getAudience().size());
        assertEquals("https://localhost:8081", claims.getAudience().get(0));
    }

    @Test
    void enhanceAndResignTokenWithCustomClaimRemoved() throws Exception {
        JWTClaimsSet tokenClaims = signAndVerifyClaims();
        assertEquals("custom-value", tokenClaims.getClaim("customClaim"));
        JsonWebToken token = new TestJsonWebToken(tokenClaims);

        String jwt = Jwt.claims(token).remove("customClaim")
                // this just checks trying to remove non-existent claims does not cause some NPE
                .remove(UUID.randomUUID().toString())
                .claim("newClaim", "new-value").sign();

        // verify
        SignedJWT signedJWT = getVerifiedJws(jwt);
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
        assertEquals(6, claims.getClaims().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);
        assertNull(claims.getClaim("customClaim"));

        assertEquals("new-value", claims.getClaim("newClaim"));
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
            SignedJWT signedJWT = getVerifiedJws(jwt);
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            assertEquals(7, claims.getClaims().size());
            checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);
            assertEquals("custom-value", claims.getClaim("customClaim"));

            assertEquals("new-value", claims.getClaim("newClaim"));
            assertEquals("https://custom-issuer", claims.getIssuer());
            assertEquals(1, claims.getAudience().size());
            assertEquals("https://custom-audience", claims.getAudience().get(0));
        } finally {
            configSource.setIssuerPropertyRequired(false);
            configSource.setAudiencePropertyRequired(false);
            configSource.setOverrideMatchingClaims(false);
        }
    }

    private JWTClaimsSet signAndVerifyClaims() throws Exception {
        return signAndVerifyClaims(null, null, null);
    }

    private JWTClaimsSet signAndVerifyClaims(Long customLifespan, String issuer, String aud) throws Exception {
        JwtClaimsBuilder builder = Jwt.claims().claim("customClaim", "custom-value");
        if (issuer == null) {
            builder.issuer("https://default-issuer");
        }
        if (aud == null) {
            builder.audience("https://localhost:8081");
        }
        String jwt = builder.sign(getPrivateKey());
        SignedJWT signedJWT = getVerifiedJws(jwt);
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
        assertEquals(6, claims.getClaims().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims, "RS256", customLifespan != null ? customLifespan : 300);

        assertEquals("custom-value", claims.getClaim("customClaim"));
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
        SignedJWT signedJWT = SignedJWT.parse(jwt);
        assertTrue(signedJWT.verify(new RSASSAVerifier((RSAPublicKey) KeyUtils.readPublicKey("/publicKey.pem"))));
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
        assertEquals(3, claims.getClaims().size());
        assertEquals(now.getEpochSecond(), claims.getIssueTime().getTime() / 1000);
        assertEquals(now.getEpochSecond() + 3000, claims.getExpirationTime().getTime() / 1000);
        assertNotNull(claims.getJWTID());
    }

    @Test
    void signMapOfClaims() throws Exception {
        String jwt = Jwt.claims(Collections.singletonMap("customClaim", "custom-value"))
                .sign(getPrivateKey());

        SignedJWT signedJWT = getVerifiedJws(jwt);
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

        assertEquals(4, claims.getClaims().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);

        assertEquals("custom-value", claims.getClaim("customClaim"));
    }

    @Test
    void signMapOfClaimsShortcut() throws Exception {
        String jwt = Jwt.sign(Collections.singletonMap("customClaim", "custom-value"));

        SignedJWT signedJWT = getVerifiedJws(jwt);
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

        assertEquals(4, claims.getClaims().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);

        assertEquals("custom-value", claims.getClaim("customClaim"));
    }

    @Test
    void signJsonString() throws Exception {
        String jwt = Jwt.claimsJson("{\"customClaim\":\"custom-value\"}")
                .sign(getPrivateKey());

        SignedJWT signedJWT = getVerifiedJws(jwt);
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

        assertEquals(4, claims.getClaims().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);

        assertEquals("custom-value", claims.getClaim("customClaim"));
    }

    @Test
    void signJsonStringShortcut() throws Exception {
        String jwt = Jwt.signJson("{\"customClaim\":\"custom-value\"}");

        SignedJWT signedJWT = getVerifiedJws(jwt);
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

        assertEquals(4, claims.getClaims().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);

        assertEquals("custom-value", claims.getClaim("customClaim"));
    }

    @Test
    void signMapOfClaimsWithKeyLocation() throws Exception {
        String jwt = Jwt.claims(Collections.singletonMap("customClaim", "custom-value"))
                .sign("/privateKey.pem");

        SignedJWT signedJWT = getVerifiedJws(jwt);
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

        assertEquals(4, claims.getClaims().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);

        assertEquals("custom-value", claims.getClaim("customClaim"));
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
        SignedJWT signedJWT = getVerifiedJws(jwt);
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

        assertEquals(5, claims.getClaims().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);

        assertEquals("Alice", claims.getClaim("username"));
        @SuppressWarnings("unchecked")
        Map<String, String> address = (Map<String, String>) claims.getClaim("address");
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
                    "SRJWT05012: Failure to create a signed JWT token: The RSA key size must be at least 2048 bits",
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

            SignedJWT signedJWT = getVerifiedJws(jwt, keyPair.getPublic());
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            assertEquals(4, claims.getClaims().size());
            checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);

            assertEquals("custom-value", claims.getClaim("customClaim"));
        } finally {
            configSource.setRelaxSignatureKeyValidation(false);
        }
    }

    @Test
    void signWithoutAddingDefaultClaim() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair(2048);

        JwtBuildConfigSource configSource = getConfigSource();
        configSource.setAddDefaultClaims(false);
        try {
            String jwt = Jwt.claims(Collections.singletonMap("customClaim", "custom-value"))
                    .sign(keyPair.getPrivate());

            SignedJWT signedJWT = getVerifiedJws(jwt, keyPair.getPublic(), true);
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            assertEquals(1, claims.getClaims().size());
            assertEquals("custom-value", claims.getClaim("customClaim"));

            Map<String, Object> headers = getJwsHeaders(jwt, 2);
            assertEquals("RS256", headers.get("alg"));
            assertEquals("JWT", headers.get("typ"));

        } finally {
            configSource.setAddDefaultClaims(true);
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

        SignedJWT signedJWT = getVerifiedJws(jwt);
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

        assertEquals(4, claims.getClaims().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);

        assertEquals("custom-value", claims.getClaim("customClaim"));
        return claims.getJWTID();
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

        SignedJWT signedJWT = getVerifiedJws(jwt);
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

        assertEquals(4, claims.getClaims().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 4), claims);

        assertEquals("https://issuer.com", claims.getIssuer());
        assertEquals("key-id", signedJWT.getHeader().getKeyID());
        assertEquals("custom-header-value", signedJWT.getHeader().getCustomParam("customHeader"));
    }

    private static PrivateKey getPrivateKey() throws Exception {
        return KeyUtils.readPrivateKey("/privateKey.pem");
    }

    private static PrivateKey getEdEcPrivateKey() throws Exception {
        return (PrivateKey) KeyUtils.readSigningKey("/edEcPrivateKey.jwk", null, null);
    }

    private static PublicKey getEdEcPublicKey() throws Exception {
        String keyContent = KeyUtils.readKeyContent("/edEcPublicKey.jwk");
        OctetKeyPair okp = (OctetKeyPair) JWK.parse(keyContent);
        return EdDSAVerifier.toPublicKey(okp);
    }

    private static PublicKey getEcPublicKey() throws Exception {
        return KeyUtils.readPublicKey("/ecPublicKey.pem", SignatureAlgorithm.ES256);
    }

    private static PublicKey getPublicKey() throws Exception {
        return KeyUtils.readPublicKey("/publicKey.pem");
    }

    private static SignedJWT getVerifiedJws(String jwt) throws Exception {
        return getVerifiedJws(jwt, getPublicKey());
    }

    static SignedJWT getVerifiedJws(String jwt, Key key) throws Exception {
        return getVerifiedJws(jwt, key, false);
    }

    static SignedJWT getVerifiedJws(String jwt, Key key, boolean relaxKeyValidation) throws Exception {
        SignedJWT signedJWT = SignedJWT.parse(jwt);
        if (key instanceof EdECPublicKey) {
            verifyEdDSA(jwt, (PublicKey) key);
        } else {
            JWSVerifier verifier = createVerifier(key);
            assertTrue(signedJWT.verify(verifier));
        }
        return signedJWT;
    }

    private static void verifyEdDSA(String jwt, PublicKey publicKey) throws Exception {
        String[] parts = jwt.split("\\.");
        String signingInput = parts[0] + "." + parts[1];
        byte[] signatureBytes = com.nimbusds.jose.util.Base64URL.from(parts[2]).decode();
        Signature sig = Signature.getInstance(publicKey.getAlgorithm());
        sig.initVerify(publicKey);
        sig.update(signingInput.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        assertTrue(sig.verify(signatureBytes), "EdDSA signature verification failed");
    }

    private static JWSVerifier createVerifier(Key key) throws JOSEException {
        if (key instanceof RSAPublicKey) {
            return new RSASSAVerifier((RSAPublicKey) key);
        } else if (key instanceof ECPublicKey) {
            return new ECDSAVerifier((ECPublicKey) key);
        } else if (key instanceof SecretKey) {
            return new MACVerifier((SecretKey) key);
        }
        throw new JOSEException("Unsupported key type for verification: " + key.getClass().getName());
    }

    private static void checkDefaultClaimsAndHeaders(Map<String, Object> headers, JWTClaimsSet claims) throws Exception {
        checkDefaultClaimsAndHeaders(headers, claims, "RS256", 300);
    }

    static void checkDefaultClaimsAndHeaders(Map<String, Object> headers, JWTClaimsSet claims, String algo,
            long expectedLifespan) throws Exception {
        checkDefaultClaimsAndHeaders(headers, claims, algo, "JWT", expectedLifespan);
    }

    static void checkDefaultClaimsAndHeaders(Map<String, Object> headers, JWTClaimsSet claims, String algo,
            String type, long expectedLifespan)
            throws Exception {
        Date iat = claims.getIssueTime();
        assertNotNull(iat);
        Date exp = claims.getExpirationTime();
        assertNotNull(exp);
        long tokenLifespan = exp.getTime() / 1000 - iat.getTime() / 1000;
        assertTrue(tokenLifespan >= expectedLifespan && tokenLifespan <= expectedLifespan + 2);
        assertNotNull(claims.getJWTID());
        assertEquals(algo, headers.get("alg"));
        assertEquals(type, headers.get("typ"));
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

        SignedJWT signedJWT = getVerifiedJws(jwt);
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

        assertEquals(12, claims.getClaims().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims);

        String scope = claims.getStringClaim("scope");
        assertTrue("read:data write:data".equals(scope) || "write:data read:data".equals(scope));

        assertEquals("string", claims.getClaim("stringClaim"));
        assertTrue((Boolean) claims.getClaim("booleanClaim"));
        assertEquals(3L, claims.getClaim("numberClaim"));

        List<String> stringList = claims.getStringListClaim("stringListClaim");
        assertEquals(2, stringList.size());
        assertEquals("1", stringList.get(0));
        assertEquals("2", stringList.get(1));

        @SuppressWarnings("unchecked")
        List<Long> numberList = (List<Long>) claims.getClaim("numberListClaim");
        assertEquals(2, numberList.size());
        assertEquals(Long.valueOf(1), numberList.get(0));
        assertEquals(Long.valueOf(2), numberList.get(1));

        @SuppressWarnings("unchecked")
        Map<String, Object> mapClaim = (Map<String, Object>) claims.getClaim("mapClaim");
        assertEquals(1, mapClaim.size());
        assertEquals("value", mapClaim.get("key"));

        @SuppressWarnings("unchecked")
        Map<String, Object> mapJsonClaim = (Map<String, Object>) claims.getClaim("jsonObjectClaim");
        assertEquals(1, mapJsonClaim.size());
        assertEquals("jsonValue", mapJsonClaim.get("jsonKey"));

        @SuppressWarnings("unchecked")
        List<Long> numberJsonList = (List<Long>) claims.getClaim("jsonArrayClaim");
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

        SignedJWT signedJWT = getVerifiedJws(jwt);
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

        assertEquals(9, claims.getClaims().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims, "RS256", 1000);

        assertEquals("https://server.example.com", claims.getIssuer());
        assertEquals("a-123", claims.getClaim("jti"));
        assertEquals("24400320", claims.getSubject());
        assertEquals("jdoe@example.com", claims.getClaim("upn"));
        assertEquals("jdoe", claims.getClaim("preferred_username"));
        assertEquals("s6BhdRkqt3", claims.getAudience().get(0));
        assertEquals(1311281970L, claims.getExpirationTime().getTime() / 1000);
        assertEquals(1311280970L, claims.getIssueTime().getTime() / 1000);
        assertEquals(1311280969L, claims.getLongClaim("auth_time").longValue());
    }

    @Test
    void signClaimsEllipticCurve() throws Exception {
        ECKey ecJwk = createECJwk();

        String jwt = Jwt.claims()
                .claim("customClaim", "custom-value")
                .claim("evidence", ecJwk.toECPublicKey())
                .jws().jwk(ecJwk.toECPublicKey())
                .sign(ecJwk.toECPrivateKey());

        SignedJWT signedJWT = getVerifiedJws(jwt, ecJwk.toECPublicKey());
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
        assertEquals(5, claims.getClaims().size());

        Map<String, Object> headers = getJwsHeaders(jwt, 3);
        checkDefaultClaimsAndHeaders(headers, claims, "ES256", 300);

        assertEquals("custom-value", claims.getClaim("customClaim"));

        @SuppressWarnings("unchecked")
        Map<String, Object> jwk = (Map<String, Object>) headers.get("jwk");
        assertEquals(4, jwk.size());
        assertEquals("EC", jwk.get("kty"));
        assertEquals("P-256", jwk.get("crv"));
        assertNotNull(jwk.get("x"));
        assertNotNull(jwk.get("y"));

        @SuppressWarnings("unchecked")
        Map<String, Object> evidence = (Map<String, Object>) claims.getClaim("evidence");
        assertEquals(evidence, jwk);
    }

    @Test
    void signClaimsEd25519() throws Exception {
        if (Runtime.version().version().get(0) >= 17) {
            KeyPairGenerator kpgEd25519 = KeyPairGenerator.getInstance("Ed25519");
            KeyPair keyPairEd25519 = kpgEd25519.generateKeyPair();
            KeyPairGenerator kpgEd448 = KeyPairGenerator.getInstance("Ed448");
            KeyPair keyPairEd448 = kpgEd448.generateKeyPair();

            String jwt = Jwt.claims()
                    .claim("customClaim", "custom-value")
                    .jws().jwk(keyPairEd25519.getPublic())
                    .sign(keyPairEd25519.getPrivate());

            SignedJWT signedJWT = getVerifiedJws(jwt, keyPairEd25519.getPublic());
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            assertEquals(4, claims.getClaims().size());
            Map<String, Object> headers = getJwsHeaders(jwt, 3);
            checkDefaultClaimsAndHeaders(headers, claims, "EdDSA", 300);

            assertEquals("custom-value", claims.getClaim("customClaim"));

            @SuppressWarnings("unchecked")
            Map<String, Object> jwk = (Map<String, Object>) headers.get("jwk");
            assertEquals(3, jwk.size());
            assertEquals("OKP", jwk.get("kty"));
            assertEquals("Ed25519", jwk.get("crv"));
            assertNotNull(jwk.get("x"));

            try {
                SignedJWT parsed = SignedJWT.parse(jwt);
                parsed.verify(createVerifier(keyPairEd448.getPublic()));
                fail("ED25519 curve was used to sign the token, must not be verified with ED448");
            } catch (Exception ex) {
                // Expected - verification should fail
            }
        }
    }

    @Test
    void signClaimsEd25519WithJwk() throws Exception {
        if (Runtime.version().version().get(0) >= 17) {
            KeyPairGenerator kpgEd448 = KeyPairGenerator.getInstance("Ed448");
            KeyPair keyPairEd448 = kpgEd448.generateKeyPair();

            String jwt = Jwt.claims()
                    .claim("customClaim", "custom-value")
                    .sign(getEdEcPrivateKey());

            SignedJWT signedJWT = getVerifiedJws(jwt, getEdEcPublicKey());
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            assertEquals(4, claims.getClaims().size());
            Map<String, Object> headers = getJwsHeaders(jwt, 2);
            checkDefaultClaimsAndHeaders(headers, claims, "EdDSA", 300);

            assertEquals("custom-value", claims.getClaim("customClaim"));

            try {
                SignedJWT parsed = SignedJWT.parse(jwt);
                parsed.verify(createVerifier(keyPairEd448.getPublic()));
                fail("ED25519 curve was used to sign the token, must not be verified with ED448");
            } catch (Exception ex) {
                // Expected - verification should fail
            }
        }
    }

    @Test
    void signClaimsEd448() throws Exception {
        if (Runtime.version().version().get(0) >= 17) {
            KeyPairGenerator kpgEd25519 = KeyPairGenerator.getInstance("Ed25519");
            KeyPair keyPairEd25519 = kpgEd25519.generateKeyPair();
            KeyPairGenerator kpgEd448 = KeyPairGenerator.getInstance("Ed448");
            KeyPair keyPairEd448 = kpgEd448.generateKeyPair();

            String jwt = Jwt.claims()
                    .claim("customClaim", "custom-value")
                    .sign(keyPairEd448.getPrivate());

            SignedJWT signedJWT = getVerifiedJws(jwt, keyPairEd448.getPublic());
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            assertEquals(4, claims.getClaims().size());
            Map<String, Object> headers = getJwsHeaders(jwt, 2);
            checkDefaultClaimsAndHeaders(headers, claims, "EdDSA", 300);

            assertEquals("custom-value", claims.getClaim("customClaim"));

            try {
                SignedJWT parsed = SignedJWT.parse(jwt);
                parsed.verify(createVerifier(keyPairEd25519.getPublic()));
                fail("ED448 curve was used to sign the token, must not be verified with ED25519");
            } catch (Exception ex) {
                // Expected - verification should fail
            }
        }
    }

    private static ECKey createECJwk() throws Exception {
        return new ECKeyGenerator(Curve.P_256).generate();
    }

    @Test
    void signClaimsSymmetricKey() throws Exception {
        SecretKey secretKey = createSecretKey();

        String jwt = Jwt.claims()
                .claim("customClaim", "custom-value")
                .sign(secretKey);

        SignedJWT signedJWT = getVerifiedJws(jwt, secretKey);
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

        assertEquals(4, claims.getClaims().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims, "HS256", 300);

        assertEquals("custom-value", claims.getClaim("customClaim"));
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

            SignedJWT signedJWT = getVerifiedJws(jwt, verificationKey);
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            assertEquals(4, claims.getClaims().size());
            Map<String, Object> headers = getJwsHeaders(jwt, 3);
            checkDefaultClaimsAndHeaders(headers, claims, "RS256", 300);
            assertEquals("custom-value", claims.getClaim("customClaim"));

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
        SignedJWT signedJWT = getVerifiedJws(jwt, secretKey);
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

        assertEquals(4, claims.getClaims().size());
        checkDefaultClaimsAndHeaders(getJwsHeaders(jwt, 2), claims, "HS256", 300);

        assertEquals("custom-value", claims.getClaim("customClaim"));
    }

    @Test
    void signClaimsWithShortSecret() throws Exception {
        String secret = "AyM1SysPpbyDfgZld3umj1qzKObw";

        JwtSignatureException thrown = assertThrows(JwtSignatureException.class,
                () -> Jwt.claims().claim("customClaim", "custom-value").signWithSecret(secret),
                "JwtSignatureException is expected");
        assertEquals(
                "The secret length must be at least 256 bits",
                thrown.getCause().getMessage());
    }

    // Nimbus MACSigner enforces minimum 256-bit key length with no bypass option,
    // so relaxed HMAC key validation cannot be supported without a custom HMAC signer.
    // @Test
    // void signClaimsWithShortSecretAndRelaxedValidation() throws Exception {
    // }

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
        SignedJWT signedJWT = getVerifiedJws(jwt, secretKey);
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

        assertEquals(4, claims.getClaims().size());
        Map<String, Object> headers = getJwsHeaders(jwt, 3);
        checkDefaultClaimsAndHeaders(headers, claims, "HS256", 300);
        assertEquals("secretkey1", headers.get("kid"));
        assertEquals("custom-value", claims.getClaim("customClaim"));
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
                    .type("custom/jwt")
                    .algorithm(SignatureAlgorithm.ES256)
                    .keyId("eckey1")
                    .sign();
        } finally {
            configSource.setSigningKeyLocation("/privateKey.pem");
        }

        PublicKey ecKey = getEcPublicKey();
        SignedJWT signedJWT = getVerifiedJws(jwt, ecKey);
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

        assertEquals(4, claims.getClaims().size());
        Map<String, Object> headers = getJwsHeaders(jwt, 3);
        checkDefaultClaimsAndHeaders(headers, claims, "ES256", "custom/jwt", 300);
        assertEquals("eckey1", headers.get("kid"));
        assertEquals("custom-value", claims.getClaim("customClaim"));
    }

    @Test
    void signClaimsEcKeyFileWithConfiguredAlgorithm() throws Exception {
        JwtBuildConfigSource configSource = getConfigSource();
        configSource.setSigningKeyLocation("/ecPrivateKey.pem");
        configSource.setSignatureAlgorithm(SignatureAlgorithm.ES256.getAlgorithm());
        String jwt = null;
        try {
            jwt = Jwt.claim("customClaim", "custom-value")
                    .sign();
        } finally {
            configSource.setSigningKeyLocation("/privateKey.pem");
            configSource.setSignatureAlgorithm(null);
        }

        PublicKey ecKey = getEcPublicKey();
        SignedJWT signedJWT = getVerifiedJws(jwt, ecKey);
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

        assertEquals(4, claims.getClaims().size());
        Map<String, Object> headers = getJwsHeaders(jwt, 2);
        checkDefaultClaimsAndHeaders(headers, claims, "ES256", 300);
        assertEquals("custom-value", claims.getClaim("customClaim"));
    }

    @Test
    @EnabledForJreRange(min = JRE.JAVA_17)
    void signClaimsWithConfiguredEddsaAlgorithm() throws Exception {
        var alg = "EdDSA";
        var configSource = getConfigSource();
        configSource.setSignatureAlgorithm(alg);
        configSource.setSigningKeyLocation("/edEcPrivateKey.jwk");

        try {
            var jwt = Jwt.claim("customClaim", "custom-value").sign();

            var keyContent = KeyUtils.readKeyContent("/edEcPublicKey.jwk");
            var signedJWT = getVerifiedJws(jwt,
                    EdDSAVerifier.toPublicKey((OctetKeyPair) JWK.parse(keyContent)));
            var claims = signedJWT.getJWTClaimsSet();

            assertEquals(4, claims.getClaims().size());
            var headers = getJwsHeaders(jwt, 2);
            checkDefaultClaimsAndHeaders(headers, claims, "EdDSA", 300);
            assertEquals("custom-value", claims.getClaim("customClaim"));
        } finally {
            configSource.setSignatureAlgorithm(null);
            configSource.setSigningKeyLocation("/privateKey.pem");
        }
    }

    @Test
    @EnabledForJreRange(min = JRE.JAVA_17)
    void signClaimsWithEddsaFromHeader() throws Exception {
        var alg = "EdDSA";
        var configSource = getConfigSource();
        configSource.setSigningKeyLocation("/edEcPrivateKey.jwk");

        try {
            var jwt = Jwt.claims()
                    .issuer("https://issuer.com")
                    .jws()
                    .header("alg", alg)
                    .header("customHeader", "custom-header-value")
                    .sign();

            var keyContent = KeyUtils.readKeyContent("/edEcPublicKey.jwk");
            var signedJWT = getVerifiedJws(jwt,
                    EdDSAVerifier.toPublicKey((OctetKeyPair) JWK.parse(keyContent)));
            var claims = signedJWT.getJWTClaimsSet();

            assertEquals(4, claims.getClaims().size());
            assertEquals("https://issuer.com", claims.getIssuer());
            assertEquals("custom-header-value", signedJWT.getHeader().getCustomParam("customHeader"));
        } finally {
            configSource.setSigningKeyLocation("/privateKey.pem");
        }
    }

    @Test
    @EnabledForJreRange(min = JRE.JAVA_17)
    void signClaimsWithEddsaFromAlgorithm() throws Exception {
        var alg = SignatureAlgorithm.EDDSA;
        var configSource = getConfigSource();
        configSource.setSigningKeyLocation("/edEcPrivateKey.jwk");

        try {
            var jwt = Jwt.claims()
                    .issuer("https://issuer.com")
                    .jws()
                    .algorithm(alg)
                    .header("customHeader", "custom-header-value")
                    .sign();

            var keyContent = KeyUtils.readKeyContent("/edEcPublicKey.jwk");
            var signedJWT = getVerifiedJws(jwt,
                    EdDSAVerifier.toPublicKey((OctetKeyPair) JWK.parse(keyContent)));
            var claims = signedJWT.getJWTClaimsSet();

            assertEquals(4, claims.getClaims().size());
            assertEquals("https://issuer.com", claims.getIssuer());
            assertEquals("custom-header-value", signedJWT.getHeader().getCustomParam("customHeader"));
        } finally {
            configSource.setSigningKeyLocation("/privateKey.pem");
        }
    }

    private static SecretKey createSecretKey() throws Exception {
        String jwkJson = "{\"kty\":\"oct\",\"k\":\"Fdh9u8rINxfivbrianbbVT1u232VQBZYKx1HGAGPt2I\"}";
        OctetSequenceKey jwk = OctetSequenceKey.parse(jwkJson);
        return jwk.toSecretKey("AES");
    }

    @Test
    void wrongKeyForRSAAlgorithm() throws Exception {
        // EC
        try {
            Jwt.claims()
                    .claim("customClaim", "custom-value")
                    .jws()
                    .header("alg", "RS256")
                    .sign(createECJwk().toECPrivateKey());
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

        SignedJWT signedJWT = SignedJWT.parse(jwtString);
        List<com.nimbusds.jose.util.Base64> x5c = signedJWT.getHeader().getX509CertChain();
        X509Certificate certFromHeader = X509CertUtils.parse(x5c.get(0).decode());
        assertTrue(signedJWT.verify(new RSASSAVerifier((RSAPublicKey) certFromHeader.getPublicKey())));
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

        assertEquals("Alice", claims.getStringClaim("upn"));
    }

    @Test
    void testInvalidCertificateChainHeader() throws Exception {
        X509Certificate cert = KeyUtils.getCertificate(ResourceUtils.readResource("/certificate.pem"));
        String jwtString = Jwt.upn("Alice")
                .jws().chain(cert)
                // this key does not correspond to the public key in the loaded certificate
                .sign("/privateKey.pem");

        SignedJWT signedJWT = SignedJWT.parse(jwtString);
        List<com.nimbusds.jose.util.Base64> x5c = signedJWT.getHeader().getX509CertChain();
        X509Certificate certFromHeader = X509CertUtils.parse(x5c.get(0).decode());
        // The key doesn't correspond to the signing key, so verification should fail
        assertFalse(signedJWT.verify(new RSASSAVerifier((RSAPublicKey) certFromHeader.getPublicKey())));
    }

    static Map<String, Object> getJwsHeaders(String compactJws, int expectedSize) throws Exception {
        int firstDot = compactJws.indexOf(".");
        String headersJson = new Base64URL(compactJws.substring(0, firstDot)).decodeToString();
        Map<String, Object> headers = JSONObjectUtils.parse(headersJson);
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

        private JWTClaimsSet claims;

        TestJsonWebToken(JWTClaimsSet claims) {
            this.claims = claims;
        }

        @Override
        public String getName() {
            return null;
        }

        @Override
        public Set<String> getClaimNames() {
            return new HashSet<>(claims.getClaims().keySet());
        }

        @SuppressWarnings("unchecked")
        @Override
        public <T> T getClaim(String claimName) {
            if (Claims.aud.name().equals(claimName)) {
                return (T) new HashSet<>(claims.getAudience());
            }
            Object value = claims.getClaim(claimName);
            // Convert Date values to epoch seconds (Long) for time claims
            if (value instanceof Date) {
                return (T) Long.valueOf(((Date) value).getTime() / 1000);
            }
            return (T) value;
        }

    }
}
