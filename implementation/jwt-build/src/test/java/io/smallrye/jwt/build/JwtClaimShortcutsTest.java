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

import java.util.List;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;

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
        verifyJwt(Jwt.audience("aud").sign(), "aud", "aud");
    }

    @Test
    void issuer() throws Exception {
        verifyJwtWithIssuer(Jwt.issuer("iss").sign());
    }

    private static void verifyJwt(String jwt, String customClaim, String customValue) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setKey(KeyUtils.readPublicKey("/publicKey.pem"));
        jws.setCompactSerialization(jwt);
        assertTrue(jws.verifySignature());
        JwtClaims claims = JwtClaims.parse(jws.getPayload());
        assertEquals(4, claims.getClaimsMap().size());
        assertEquals(customValue, claims.getClaimValue(customClaim));
        assertNotNull(claims.getIssuedAt());
        assertNotNull(claims.getExpirationTime());
        assertNotNull(claims.getJwtId());
    }

    private static void verifyJwtWithIssuer(String jwt) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setKey(KeyUtils.readPublicKey("/publicKey.pem"));
        jws.setCompactSerialization(jwt);
        assertTrue(jws.verifySignature());
        JwtClaims claims = JwtClaims.parse(jws.getPayload());
        assertEquals(4, claims.getClaimsMap().size());
        assertEquals("iss", claims.getIssuer());
        assertNotNull(claims.getIssuedAt());
        assertNotNull(claims.getExpirationTime());
        assertNotNull(claims.getJwtId());
    }

    private static void verifyJwtWithArray(String jwt, String customClaim, String customValue) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setKey(KeyUtils.readPublicKey("/publicKey.pem"));
        jws.setCompactSerialization(jwt);
        assertTrue(jws.verifySignature());
        JwtClaims claims = JwtClaims.parse(jws.getPayload());
        assertEquals(4, claims.getClaimsMap().size());
        @SuppressWarnings("unchecked")
        List<String> list = (List<String>) claims.getClaimValue(customClaim);
        assertEquals(1, list.size());
        assertEquals(customValue, list.get(0));
        assertNotNull(claims.getIssuedAt());
        assertNotNull(claims.getExpirationTime());
        assertNotNull(claims.getJwtId());
    }
}
