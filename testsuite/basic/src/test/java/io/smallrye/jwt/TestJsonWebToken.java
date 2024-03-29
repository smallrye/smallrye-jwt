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
package io.smallrye.jwt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.eclipse.microprofile.jwt.tck.util.SignatureAlgorithm;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.junit.jupiter.api.Test;

import io.smallrye.jwt.auth.principal.DefaultJWTParser;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipalFactory;
import io.smallrye.jwt.auth.principal.ParseException;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.util.KeyUtils;

/**
 * Test various parsing expectations of a JWT string into a JsonWebToken
 */
class TestJsonWebToken {
    @Test
    void validation() throws Exception {
        String token = TokenUtils.signClaims("/Token1.json");
        RSAPublicKey publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, "https://server.example.com");
        contextInfo.setExpGracePeriodSecs(60);
        assertNotNull(validateToken(token, contextInfo));
    }

    @Test
    void failIssuer() throws Exception {
        Set<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.ISSUER);
        String token = TokenUtils.signClaims("/Token1.json", SignatureAlgorithm.RS256, invalidFields);
        RSAPublicKey publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, "https://server.example.com");
        contextInfo.setExpGracePeriodSecs(60);
        assertThrows(ParseException.class, () -> validateToken(token, contextInfo));
    }

    @Test
    void failSignature() throws Exception {
        Set<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.SIGNER);
        String token = TokenUtils.signClaims("/Token1.json", SignatureAlgorithm.RS256, invalidFields);
        RSAPublicKey publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, "https://server.example.com");
        contextInfo.setExpGracePeriodSecs(60);
        assertThrows(ParseException.class, () -> validateToken(token, contextInfo));
    }

    @Test
    void failExpired() throws Exception {
        Map<String, Long> timeClaims = new HashMap<>();
        Set<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.EXP);
        String token = TokenUtils.signClaims("/Token1.json", SignatureAlgorithm.RS256, invalidFields, timeClaims);
        RSAPublicKey publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, "https://server.example.com");
        contextInfo.setExpGracePeriodSecs(60);
        assertThrows(ParseException.class, () -> validateToken(token, contextInfo));
    }

    @Test
    void failJustExpired() throws Exception {
        Map<String, Long> timeClaims = new HashMap<>();
        // Set exp to 61 seconds in past
        long exp = TokenUtils.currentTimeInSecs() - 61;
        timeClaims.put(Claims.exp.name(), exp);
        String token = TokenUtils.signClaims("/Token1.json", SignatureAlgorithm.RS256, null, timeClaims);
        RSAPublicKey publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, "https://server.example.com");
        contextInfo.setExpGracePeriodSecs(60);
        assertThrows(ParseException.class, () -> validateToken(token, contextInfo));
    }

    @Test
    void expGrace() throws Exception {
        Map<String, Long> timeClaims = new HashMap<>();
        // Set exp to 45 seconds in past
        long exp = TokenUtils.currentTimeInSecs() - 45;
        timeClaims.put(Claims.exp.name(), exp);
        String token = TokenUtils.signClaims("/Token1.json", SignatureAlgorithm.RS256, null, timeClaims);
        RSAPublicKey publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, "https://server.example.com");
        contextInfo.setExpGracePeriodSecs(60);
        validateToken(token, contextInfo);
    }

    @Test
    void clockSkew() throws Exception {
        Map<String, Long> timeClaims = new HashMap<>();
        // Set exp to 45 seconds in past
        long exp = TokenUtils.currentTimeInSecs() - 45;
        timeClaims.put(Claims.exp.name(), exp);
        String token = TokenUtils.signClaims("/Token1.json", SignatureAlgorithm.RS256, null, timeClaims);
        RSAPublicKey publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, "https://server.example.com");
        contextInfo.setClockSkew(100);
        validateToken(token, contextInfo);
    }

    @Test
    void parseExpiredTokenWithDefaultClockSkew() throws Exception {
        // default is 60 secs
        String jwtString = Jwt.upn("jdoe@example.com").issuer("https://server.example.com")
                .issuedAt(Instant.now().minusSeconds(100))
                .expiresAt(Instant.now().minusSeconds(20))
                .sign(KeyUtils.readPrivateKey("/privateKey.pem"));
        JWTAuthContextInfo config = new JWTAuthContextInfo("/publicKey.pem", "https://server.example.com");
        JsonWebToken jwt = new DefaultJWTParser(config).parse(jwtString);
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    void failTooLowClockSkew() throws Exception {
        Map<String, Long> timeClaims = new HashMap<>();
        // Set exp to 45 seconds in past
        long exp = TokenUtils.currentTimeInSecs() - 45;
        timeClaims.put(Claims.exp.name(), exp);
        String token = TokenUtils.signClaims("/Token1.json", SignatureAlgorithm.RS256, null, timeClaims);
        RSAPublicKey publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, "https://server.example.com");
        contextInfo.setClockSkew(5);
        assertThrows(ParseException.class, () -> validateToken(token, contextInfo));
    }

    private JsonWebToken validateToken(String token, JWTAuthContextInfo contextInfo) throws ParseException {
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        return factory.parse(token, contextInfo);
    }
}
