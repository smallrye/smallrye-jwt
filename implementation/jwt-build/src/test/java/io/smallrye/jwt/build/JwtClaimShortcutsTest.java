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

import java.util.List;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.junit.Assert;
import org.junit.Test;

import io.smallrye.jwt.util.KeyUtils;

public class JwtClaimShortcutsTest {

    @Test
    public void testCustomClaim() throws Exception {
        verifyJwt(
                Jwt.claim("customClaim", "custom-value").sign(), "customClaim", "custom-value");
    }

    @Test
    public void testUpn() throws Exception {
        verifyJwt(Jwt.upn("upn").sign(), "upn", "upn");
    }

    @Test
    public void testSubject() throws Exception {
        verifyJwt(Jwt.subject("sub").sign(), "sub", "sub");
    }

    @Test
    public void testPreferredUserName() throws Exception {
        verifyJwt(Jwt.preferredUserName("alice").sign(), "preferred_username", "alice");
    }

    @Test
    public void testGroups() throws Exception {
        verifyJwtWithArray(Jwt.groups("user").sign(), "groups", "user");
    }

    @Test
    public void testAudience() throws Exception {
        verifyJwt(Jwt.audience("aud").sign(), "aud", "aud");
    }

    @Test
    public void testIssuer() throws Exception {
        verifyJwtWithIssuer(Jwt.issuer("iss").sign());
    }

    private static void verifyJwt(String jwt, String customClaim, String customValue) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setKey(KeyUtils.readPublicKey("/publicKey.pem"));
        jws.setCompactSerialization(jwt);
        Assert.assertTrue(jws.verifySignature());
        JwtClaims claims = JwtClaims.parse(jws.getPayload());
        Assert.assertEquals(4, claims.getClaimsMap().size());
        Assert.assertEquals(customValue, claims.getClaimValue(customClaim));
        Assert.assertNotNull(claims.getIssuedAt());
        Assert.assertNotNull(claims.getExpirationTime());
        Assert.assertNotNull(claims.getJwtId());
    }

    private static void verifyJwtWithIssuer(String jwt) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setKey(KeyUtils.readPublicKey("/publicKey.pem"));
        jws.setCompactSerialization(jwt);
        Assert.assertTrue(jws.verifySignature());
        JwtClaims claims = JwtClaims.parse(jws.getPayload());
        Assert.assertEquals(4, claims.getClaimsMap().size());
        Assert.assertEquals("iss", claims.getIssuer());
        Assert.assertNotNull(claims.getIssuedAt());
        Assert.assertNotNull(claims.getExpirationTime());
        Assert.assertNotNull(claims.getJwtId());
    }

    private static void verifyJwtWithArray(String jwt, String customClaim, String customValue) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setKey(KeyUtils.readPublicKey("/publicKey.pem"));
        jws.setCompactSerialization(jwt);
        Assert.assertTrue(jws.verifySignature());
        JwtClaims claims = JwtClaims.parse(jws.getPayload());
        Assert.assertEquals(4, claims.getClaimsMap().size());
        @SuppressWarnings("unchecked")
        List<String> list = (List<String>) claims.getClaimValue(customClaim);
        Assert.assertEquals(1, list.size());
        Assert.assertEquals(customValue, list.get(0));
        Assert.assertNotNull(claims.getIssuedAt());
        Assert.assertNotNull(claims.getExpirationTime());
        Assert.assertNotNull(claims.getJwtId());
    }

}
