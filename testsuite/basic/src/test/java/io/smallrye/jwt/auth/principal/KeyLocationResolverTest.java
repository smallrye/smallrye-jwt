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

import java.security.PrivateKey;
import java.time.Instant;

import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.InvalidAlgorithmException;
import org.jose4j.lang.UnresolvableKeyException;
import org.testng.Assert;
import org.testng.annotations.Test;

import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.build.JwtClaimsBuilder;
import io.smallrye.jwt.config.JWTAuthContextInfoProvider;
import io.smallrye.jwt.util.KeyUtils;

public class KeyLocationResolverTest {

    @Test
    public void testVerifyWithJwkKeyWithMatchingKid() throws Exception {
        verifyToken("key1", null, "publicKey.jwk");
    }

    @Test
    public void testVerifyWithJwkKeyWithNonMatchingKid() throws Exception {
        try {
            verifyToken("key2", null, "publicKey.jwk");
            Assert.fail("ParseException is expected");
        } catch (ParseException ex) {
            Assert.assertTrue(ex.getCause().getCause() instanceof UnresolvableKeyException);
        }
    }

    @Test
    public void testVerifyWithJwkKeyWithMatchingKidFromSet() throws Exception {
        verifyToken("key1", null, "publicKeySet.jwk");
    }

    @Test
    public void testVerifyWithJwkKeyWithKidFromSingleKeySetWithoutKid() throws Exception {
        verifyToken("key1", null, "publicSingleKeySetWithoutKid.jwk");
    }

    @Test
    public void testVerifyWithJwkFromSetWithKidAndRequiredKid() throws Exception {
        verifyToken("key1", "key1", "publicKeySet.jwk");
    }

    @Test
    public void testVerifyWithJwkFromSetWithWrongKidAndRequiredKid() throws Exception {
        try {
            verifyToken("key2", "key1", "publicKeySet.jwk");
            Assert.fail("ParseException is expected");
        } catch (ParseException ex) {
            Assert.assertTrue(ex.getCause().getCause() instanceof UnresolvableKeyException);
        }
    }

    @Test
    public void testVerifyWithJwkKeyWithNonMatchingKidFromSet() throws Exception {
        try {
            verifyToken("key3", null, "publicKeySet.jwk");
            Assert.fail("ParseException is expected");
        } catch (ParseException ex) {
            Assert.assertTrue(ex.getCause().getCause() instanceof UnresolvableKeyException);
        }
    }

    @Test
    public void testVerifyWithClassPathPemKey() throws Exception {
        verifyToken("key3", null, "publicKey.pem");
    }

    @Test
    public void testVerifyWithClassPathPemKey2() throws Exception {
        verifyToken("key3", null, "classpath:publicKey.pem");
    }

    @Test
    public void testVerifyWithFileSystemPemKey() throws Exception {
        verifyToken("key3", null, "target/test-classes/publicKey.pem");
    }

    @Test
    public void testVerifyWithoutPrivateKey() throws Exception {
        PrivateKey privateKey = TokenUtils.readPrivateKey("/privateKey.pem");
        String token = TokenUtils.generateTokenString(privateKey, "1", "/Token1.json", null, null);
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider.createWithKeyLocation("NONE",
                "https://server.example.com");
        try {
            Assert.assertNotNull(new DefaultJWTTokenParser().parse(token, provider.getContextInfo()));
            Assert.fail("UnresolvableKeyException is expected");
        } catch (ParseException ex) {
            Assert.assertTrue(ex.getCause() instanceof UnresolvableKeyException);
        }
    }

    @Test
    public void testVerifyWithFileSystemPemKey2() throws Exception {
        verifyToken("key3", null, "file:target/test-classes/publicKey.pem");
    }

    private static void verifyToken(String kid, String requiredKeyId, String publicKeyLocation) throws Exception {
        PrivateKey privateKey = TokenUtils.readPrivateKey("/privateKey.pem");
        String token = TokenUtils.signClaims(privateKey, kid, "/Token1.json", null, null);
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider.createWithKeyLocation(publicKeyLocation,
                "https://server.example.com");
        JWTAuthContextInfo contextInfo = provider.getContextInfo();
        contextInfo.setTokenKeyId(requiredKeyId);
        Assert.assertNotNull(new DefaultJWTTokenParser().parse(token, contextInfo));
    }

    @Test
    public void testVerifyEcSignedTokenWithEcKey() throws Exception {
        JwtClaimsBuilder builder = Jwt.claims("/Token1.json");
        builder.issuedAt(Instant.now().getEpochSecond());
        builder.expiresAt(Instant.now().getEpochSecond() + 300);
        String jwt = builder.sign(KeyUtils.readPrivateKey("/ecPrivateKey.pem", SignatureAlgorithm.ES256));
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider.createWithKeyLocation("ecPublicKey.pem",
                "https://server.example.com");
        JWTAuthContextInfo contextInfo = provider.getContextInfo();
        contextInfo.setSignatureAlgorithm(SignatureAlgorithm.ES256);
        Assert.assertNotNull(new DefaultJWTTokenParser().parse(jwt, contextInfo));
    }

    @Test
    public void testVerifyEcSignedTokenWithWrongKey() throws Exception {
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
            Assert.fail("ParseException is expected due to the wrong key type");
        } catch (ParseException ex) {
            Assert.assertTrue(ex.getCause().getCause() instanceof UnresolvableKeyException);
        }
    }

    @Test
    public void testVerifyEcSignedTokenWithWrongAlgo() throws Exception {
        JwtClaimsBuilder builder = Jwt.claims("/Token1.json");
        builder.issuedAt(Instant.now().getEpochSecond());
        builder.expiresAt(Instant.now().getEpochSecond() + 300);
        String jwt = builder.sign(KeyUtils.readPrivateKey("/ecPrivateKey.pem", SignatureAlgorithm.ES256));
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider.createWithKeyLocation("publicKey.pem",
                "https://server.example.com");
        // default is RS256
        try {
            new DefaultJWTTokenParser().parse(jwt, provider.getContextInfo());
            Assert.fail("ParseException is expected due to the wrong expected algorithm");
        } catch (ParseException ex) {
            Assert.assertTrue(ex.getCause().getCause() instanceof InvalidAlgorithmException);
        }
    }

    @Test
    public void testVerifyTokenSignedWithSecretKey() throws Exception {
        String jwtString = Jwt.issuer("https://server.example.com").upn("Alice").sign("secretKey.jwk");
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider.createWithSecretKeyLocation("secretKey.jwk",
                "https://server.example.com");
        JWTAuthContextInfo contextInfo = provider.getContextInfo();
        contextInfo.setSignatureAlgorithm(SignatureAlgorithm.HS256);
        JwtClaims jwt = new DefaultJWTTokenParser().parse(jwtString, contextInfo).getJwtClaims();
        Assert.assertEquals("Alice", jwt.getClaimValueAsString("upn"));
    }
}
