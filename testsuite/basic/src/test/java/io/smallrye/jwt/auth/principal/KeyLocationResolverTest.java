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
package io.smallrye.jwt.auth.principal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.InvalidAlgorithmException;
import org.jose4j.lang.UnresolvableKeyException;
import org.junit.jupiter.api.Test;

import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.build.JwtClaimsBuilder;
import io.smallrye.jwt.config.JWTAuthContextInfoProvider;
import io.smallrye.jwt.util.KeyUtils;

class KeyLocationResolverTest {
    @Test
    void verifyWithJwkKeyWithMatchingKid() throws Exception {
        verifyToken("key1", null, "publicKey.jwk");
    }

    @Test
    void verifyWithJwkKeyWithNonMatchingKid() throws Exception {
        try {
            verifyToken("key2", null, "publicKey.jwk");
            fail("ParseException is expected");
        } catch (ParseException ex) {
            assertTrue(ex.getCause() instanceof UnresolvableKeyException);
        }
    }

    @Test
    void verifyWithJwkKeyWithMatchingKidFromSet() throws Exception {
        verifyToken("key1", null, "publicKeySet.jwk");
    }

    @Test
    void verifyWithJwkKeyWithKidFromSingleKeySetWithoutKid() throws Exception {
        verifyToken("key1", null, "publicSingleKeySetWithoutKid.jwk");
    }

    @Test
    void verifyWithJwkFromSetWithKidAndRequiredKid() throws Exception {
        verifyToken("key1", "key1", "publicKeySet.jwk");
    }

    @Test
    void verifyWithJwkFromSetWithWrongKidAndRequiredKid() throws Exception {
        try {
            verifyToken("key2", "key1", "publicKeySet.jwk");
            fail("ParseException is expected");
        } catch (ParseException ex) {
            assertTrue(ex.getCause() instanceof UnresolvableKeyException);
        }
    }

    @Test
    void verifyWithJwkKeyWithNonMatchingKidFromSet() throws Exception {
        try {
            verifyToken("key3", null, "publicKeySet.jwk");
            fail("ParseException is expected");
        } catch (ParseException ex) {
            assertTrue(ex.getCause() instanceof UnresolvableKeyException);
        }
    }

    @Test
    void verifyWithClassPathPemKey() throws Exception {
        verifyToken("key3", null, "publicKey.pem");
    }

    @Test
    void verifyWithClassPathPemKey2() throws Exception {
        verifyToken("key3", null, "classpath:publicKey.pem");
    }

    @Test
    void verifyWithFileSystemPemKey() throws Exception {
        verifyToken("key3", null, "target/test-classes/publicKey.pem");
    }

    @Test
    void verifyWithoutPrivateKey() throws Exception {
        PrivateKey privateKey = TokenUtils.readPrivateKey("/privateKey.pem");
        String token = TokenUtils.signClaims(privateKey, "1", "/Token1.json", null, null);
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider.createWithKeyLocation("NONE",
                "https://server.example.com");
        try {
            assertNotNull(new DefaultJWTTokenParser().parse(token, provider.getContextInfo()));
            fail("UnresolvableKeyException is expected");
        } catch (ParseException ex) {
            assertTrue(ex.getCause() instanceof UnresolvableKeyException);
        }
    }

    @Test
    void verifyWithFileSystemPemKey2() throws Exception {
        verifyToken("key3", null, "file:target/test-classes/publicKey.pem");
    }

    private static void verifyToken(String kid, String requiredKeyId, String publicKeyLocation) throws Exception {
        PrivateKey privateKey = TokenUtils.readPrivateKey("/privateKey.pem");
        String token = TokenUtils.signClaims(privateKey, kid, "/Token1.json", null, null);
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider.createWithKeyLocation(publicKeyLocation,
                "https://server.example.com");
        JWTAuthContextInfo contextInfo = provider.getContextInfo();
        contextInfo.setTokenKeyId(requiredKeyId);
        assertNotNull(new DefaultJWTTokenParser().parse(token, contextInfo));
    }

    @Test
    void verifyEcSignedTokenWithEcKey() throws Exception {
        JwtClaimsBuilder builder = Jwt.claims("/Token1.json");
        builder.issuedAt(Instant.now().getEpochSecond());
        builder.expiresAt(Instant.now().getEpochSecond() + 300);
        String jwt = builder.sign(KeyUtils.readPrivateKey("/ecPrivateKey.pem", SignatureAlgorithm.ES256));
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider.createWithKeyLocation("ecPublicKey.pem",
                "https://server.example.com");
        JWTAuthContextInfo contextInfo = provider.getContextInfo();
        contextInfo.setSignatureAlgorithm(SignatureAlgorithm.ES256);
        assertNotNull(new DefaultJWTTokenParser().parse(jwt, contextInfo));
    }

    @Test
    void verifyEcSignedTokenWithWrongKey() throws Exception {
        JwtClaimsBuilder builder = Jwt.claims("/Token1.json");
        builder.issuedAt(Instant.now().getEpochSecond());
        builder.expiresAt(Instant.now().getEpochSecond() + 300);
        String jwt = builder.sign(KeyUtils.readPrivateKey("/ecPrivateKey.pem", SignatureAlgorithm.ES256));
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider.createWithKeyLocation("publicKey.pem",
                "https://server.example.com");
        JWTAuthContextInfo contextInfo = provider.getContextInfo();
        contextInfo.setSignatureAlgorithm(SignatureAlgorithm.ES256);
        try {
            new DefaultJWTTokenParser().parse(jwt, contextInfo);
            fail("ParseException is expected due to the wrong key type");
        } catch (ParseException ex) {
            assertTrue(ex.getCause() instanceof UnresolvableKeyException);
        }
    }

    @Test
    void verifyEcSignedTokenWithWrongAlgo() throws Exception {
        JwtClaimsBuilder builder = Jwt.claims("/Token1.json");
        builder.issuedAt(Instant.now().getEpochSecond());
        builder.expiresAt(Instant.now().getEpochSecond() + 300);
        String jwt = builder.sign(KeyUtils.readPrivateKey("/ecPrivateKey.pem", SignatureAlgorithm.ES256));
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider.createWithKeyLocation("publicKey.pem",
                "https://server.example.com");
        // default is RS256
        try {
            new DefaultJWTTokenParser().parse(jwt, provider.getContextInfo());
            fail("ParseException is expected due to the wrong expected algorithm");
        } catch (ParseException ex) {
            assertTrue(ex.getCause().getCause() instanceof InvalidAlgorithmException);
        }
    }

    @Test
    void verifyTokenSignedWithSecretKey() throws Exception {
        String jwtString = Jwt.issuer("https://server.example.com").upn("Alice").sign("secretKey.jwk");
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider.createWithSecretKeyLocation("secretKey.jwk",
                "https://server.example.com");
        JWTAuthContextInfo contextInfo = provider.getContextInfo();
        contextInfo.setSignatureAlgorithm(SignatureAlgorithm.HS256);
        JwtClaims jwt = new DefaultJWTTokenParser().parse(jwtString, contextInfo).getJwtClaims();
        assertEquals("Alice", jwt.getClaimValueAsString("upn"));
    }

    @Test
    void verifyTokenSignedWithInlinedSecretKey() throws Exception {
        String jwtString = Jwt.issuer("https://server.example.com").upn("Alice").sign("secretKey.jwk");
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider
                .create("{\n"
                        + " \"kty\":\"oct\",\n"
                        + " \"k\":\"Fdh9u8rINxfivbrianbbVT1u232VQBZYKx1HGAGPt2I\"\n"
                        + " }",
                        null,
                        true,
                        false,
                        "https://server.example.com",
                        Optional.empty());
        JWTAuthContextInfo contextInfo = provider.getContextInfo();
        contextInfo.setSignatureAlgorithm(SignatureAlgorithm.HS256);
        JwtClaims jwt = new DefaultJWTTokenParser().parse(jwtString, contextInfo).getJwtClaims();
        assertEquals("Alice", jwt.getClaimValueAsString("upn"));
    }

    @Test
    void verifyTokenSignedWithInlinedBase64UrlEncodedSecretKey() throws Exception {
        String jwtString = Jwt.issuer("https://server.example.com").upn("Alice").sign("secretKey.jwk");
        byte[] bytes = ("{\n"
                + " \"kty\":\"oct\",\n"
                + " \"k\":\"Fdh9u8rINxfivbrianbbVT1u232VQBZYKx1HGAGPt2I\"\n"
                + " }").getBytes(StandardCharsets.UTF_8);
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider
                .create(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes),
                        null,
                        true,
                        false,
                        "https://server.example.com",
                        Optional.empty());
        JWTAuthContextInfo contextInfo = provider.getContextInfo();
        contextInfo.setSignatureAlgorithm(SignatureAlgorithm.HS256);
        JwtClaims jwt = new DefaultJWTTokenParser().parse(jwtString, contextInfo).getJwtClaims();
        assertEquals("Alice", jwt.getClaimValueAsString("upn"));
    }

    @Test
    void decryptToken() throws Exception {
        String jwtString = Jwt.issuer("https://server.example.com").upn("Alice").jwe().encrypt("publicKey.pem");
        String decryptionKey = KeyUtils.readKeyContent("privateKey.pem");
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider.createWithDecryptionKey(decryptionKey,
                "https://server.example.com");
        JWTAuthContextInfo contextInfo = provider.getContextInfo();
        JwtClaims jwt = new DefaultJWTTokenParser().parse(jwtString, contextInfo).getJwtClaims();
        assertEquals("Alice", jwt.getClaimValueAsString("upn"));
    }
}
