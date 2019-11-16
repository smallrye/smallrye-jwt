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

import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.HashSet;

import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.jose4j.jwt.JwtClaims;
import org.testng.annotations.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.ECKey.Curve;

import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipal;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipalFactory;
import io.smallrye.jwt.auth.principal.ParseException;

/**
 * Test various parsing expectations of a JWT string into a JsonWebToken
 */
public class TestJsonWebToken {
    @Test
    public void testValidation() throws Exception {
        String token = TokenUtils.generateTokenString("/Token1.json");
        RSAPublicKey publicKey = (RSAPublicKey) KeyUtils.readPublicKey("/publicKey.pem", SignatureAlgorithm.RS256);
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, "https://server.example.com");
        contextInfo.setExpGracePeriodSecs(60);
        JsonWebToken jwt = validateToken(token, contextInfo);
    }

    @Test
    public void testECValidation() throws Exception {
        ECPrivateKey privateKey = (ECPrivateKey) KeyUtils.readPrivateKey("/ecPrivateKey.pem", SignatureAlgorithm.ES256);
        ECPublicKey publicKey = (ECPublicKey) KeyUtils.readPublicKey("/ecPublicKey.pem", SignatureAlgorithm.ES256);
        ECKey ecJWK = new ECKey.Builder(Curve.P_256, publicKey).privateKey(privateKey).keyID("123").build();
        JWSSigner signer = new ECDSASigner(ecJWK);
        String token = TokenUtils.readResource("/Token1.json");
        JwtClaims claims = JwtClaims.parse(token);
        claims.setExpirationTimeMinutesInTheFuture(1);
        JWSObject jwso = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(ecJWK.getKeyID()).build(),
                new Payload(claims.toJson()));
        jwso.sign(signer);
        token = jwso.serialize();
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, "https://server.example.com");
        contextInfo.setExpGracePeriodSecs(60);
        JsonWebToken jwt = validateToken(token, contextInfo);
    }

    @Test
    public void tesHMACValidation() throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] secret = new byte[32];
        random.nextBytes(secret);
        JWSSigner signer = new MACSigner(secret);
        String token = TokenUtils.readResource("/Token1.json");
        JwtClaims claims = JwtClaims.parse(token);
        claims.setExpirationTimeMinutesInTheFuture(1);
        JWSObject jwso = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload(claims.toJson()));
        jwso.sign(signer);
        token = jwso.serialize();
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(secret, "https://server.example.com");
        contextInfo.setExpGracePeriodSecs(60);
        JsonWebToken jwt = validateToken(token, contextInfo);
    }

    @Test(expectedExceptions = { ParseException.class }, description = "Illustrate validation of issuer")
    public void testFailIssuer() throws Exception {
        HashSet<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.ISSUER);
        String token = TokenUtils.generateTokenString("/Token1.json", invalidFields);
        RSAPublicKey publicKey = (RSAPublicKey) TokenUtils.readPublicKey("/publicKey.pem");
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, "https://server.example.com");
        contextInfo.setExpGracePeriodSecs(60);
        JsonWebToken jwt = validateToken(token, contextInfo);
    }

    @Test(expectedExceptions = { ParseException.class }, description = "Illustrate validation of signer")
    public void testNimbusFailSignature() throws Exception {
        HashSet<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.SIGNER);
        String token = TokenUtils.generateTokenString("/Token1.json", invalidFields);
        RSAPublicKey publicKey = (RSAPublicKey) TokenUtils.readPublicKey("/publicKey.pem");
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, "https://server.example.com");
        contextInfo.setExpGracePeriodSecs(60);
        JsonWebToken jwt = validateToken(token, contextInfo);
    }

    @Test(expectedExceptions = { ParseException.class }, description = "Illustrate validation of exp")
    public void testNimbusFailExpired() throws Exception {
        HashMap<String, Long> timeClaims = new HashMap<>();
        HashSet<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.EXP);
        String token = TokenUtils.generateTokenString("/Token1.json", invalidFields, timeClaims);
        RSAPublicKey publicKey = (RSAPublicKey) TokenUtils.readPublicKey("/publicKey.pem");
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, "https://server.example.com");
        contextInfo.setExpGracePeriodSecs(60);
        JsonWebToken jwt = validateToken(token, contextInfo);
    }

    @Test(expectedExceptions = { ParseException.class }, description = "Illustrate validation of exp that has just expired")
    public void testNimbusFailJustExpired() throws Exception {
        HashMap<String, Long> timeClaims = new HashMap<>();
        // Set exp to 61 seconds in past
        long exp = TokenUtils.currentTimeInSecs() - 61;
        timeClaims.put(Claims.exp.name(), exp);
        String token = TokenUtils.generateTokenString("/Token1.json", null, timeClaims);
        RSAPublicKey publicKey = (RSAPublicKey) TokenUtils.readPublicKey("/publicKey.pem");
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, "https://server.example.com");
        contextInfo.setExpGracePeriodSecs(60);
        JsonWebToken jwt = validateToken(token, contextInfo);
    }

    @Test(description = "Illustrate validation of exp that is in grace period")
    public void testNimbusExpGrace() throws Exception {
        HashMap<String, Long> timeClaims = new HashMap<>();
        // Set exp to 45 seconds in past
        long exp = TokenUtils.currentTimeInSecs() - 45;
        timeClaims.put(Claims.exp.name(), exp);
        String token = TokenUtils.generateTokenString("/Token1.json", null, timeClaims);
        RSAPublicKey publicKey = (RSAPublicKey) TokenUtils.readPublicKey("/publicKey.pem");
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, "https://server.example.com");
        contextInfo.setExpGracePeriodSecs(60);
        JsonWebToken jwt = validateToken(token, contextInfo);
    }

    private JsonWebToken validateToken(String token, JWTAuthContextInfo contextInfo) throws ParseException {
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JWTCallerPrincipal callerPrincipal = factory.parse(token, contextInfo);
        return callerPrincipal;
    }

}
