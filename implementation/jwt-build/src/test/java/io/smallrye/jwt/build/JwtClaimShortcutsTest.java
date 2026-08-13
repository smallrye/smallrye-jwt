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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.interfaces.RSAPublicKey;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.smallrye.jwt.util.KeyUtils;

class JwtClaimShortcutsTest {
    @Test
    void customClaim() throws Exception {
        verifyJwt(
                Jwt.claim("customClaim", "custom-value").sign(), "customClaim", "custom-value");
    }

    @Test
    void upn() throws Exception {
        verifyJwt(Jwt.upn("upn").sign(), "upn", "upn");
    }

    @Test
    void subject() throws Exception {
        verifyJwt(Jwt.subject("sub").sign(), "sub", "sub");
    }

    @Test
    void preferredUserName() throws Exception {
        verifyJwt(Jwt.preferredUserName("alice").sign(), "preferred_username", "alice");
    }

    @Test
    void groups() throws Exception {
        verifyJwtWithArray(Jwt.groups("user").sign(), "groups", "user");
    }

    @Test
    void audience() throws Exception {
        String jwt = Jwt.audience("aud").sign();
        SignedJWT signedJWT = SignedJWT.parse(jwt);
        assertTrue(signedJWT.verify(new RSASSAVerifier((RSAPublicKey) KeyUtils.readPublicKey("/publicKey.pem"))));
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
        assertEquals(4, claims.getClaims().size());
        assertEquals(1, claims.getAudience().size());
        assertEquals("aud", claims.getAudience().get(0));
        assertNotNull(claims.getIssueTime());
        assertNotNull(claims.getExpirationTime());
        assertNotNull(claims.getJWTID());
    }

    @Test
    void issuer() throws Exception {
        verifyJwtWithIssuer(Jwt.issuer("iss").sign());
    }

    private static void verifyJwt(String jwt, String customClaim, String customValue) throws Exception {
        SignedJWT signedJWT = SignedJWT.parse(jwt);
        assertTrue(signedJWT.verify(new RSASSAVerifier((RSAPublicKey) KeyUtils.readPublicKey("/publicKey.pem"))));
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
        assertEquals(4, claims.getClaims().size());
        assertEquals(customValue, claims.getClaim(customClaim));
        assertNotNull(claims.getIssueTime());
        assertNotNull(claims.getExpirationTime());
        assertNotNull(claims.getJWTID());
    }

    private static void verifyJwtWithIssuer(String jwt) throws Exception {
        SignedJWT signedJWT = SignedJWT.parse(jwt);
        assertTrue(signedJWT.verify(new RSASSAVerifier((RSAPublicKey) KeyUtils.readPublicKey("/publicKey.pem"))));
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
        assertEquals(4, claims.getClaims().size());
        assertEquals("iss", claims.getIssuer());
        assertNotNull(claims.getIssueTime());
        assertNotNull(claims.getExpirationTime());
        assertNotNull(claims.getJWTID());
    }

    private static void verifyJwtWithArray(String jwt, String customClaim, String customValue) throws Exception {
        SignedJWT signedJWT = SignedJWT.parse(jwt);
        assertTrue(signedJWT.verify(new RSASSAVerifier((RSAPublicKey) KeyUtils.readPublicKey("/publicKey.pem"))));
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
        assertEquals(4, claims.getClaims().size());
        @SuppressWarnings("unchecked")
        List<String> list = (List<String>) claims.getClaim(customClaim);
        assertEquals(1, list.size());
        assertEquals(customValue, list.get(0));
        assertNotNull(claims.getIssueTime());
        assertNotNull(claims.getExpirationTime());
        assertNotNull(claims.getJWTID());
    }
}
