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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Key;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;

import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.util.KeyUtils;

class JwtSignJwkTest {
    @Test
    void signHS256() throws Exception {
        String jwt = Jwt.preferredUserName("alice").sign("/privateKey.jwk");
        JsonWebSignature jws = getVerifiedJws(jwt, readSecretKey("/privateKey.jwk"));
        assertEquals("secretkey1", jws.getHeader("kid"));
        // HS256 is a default value
        assertEquals("HS256", jws.getHeader("alg"));
        JwtClaims claims = JwtClaims.parse(jws.getPayload());
        assertEquals("alice", claims.getClaimValue("preferred_username"));

    }

    @Test
    void signHS512() throws Exception {
        String jwt = Jwt.preferredUserName("alice").sign("/privateKeyHS512.jwk");
        JsonWebSignature jws = getVerifiedJws(jwt, readSecretKey("/privateKeyHS512.jwk", SignatureAlgorithm.HS512));
        assertEquals("secretkey2", jws.getHeader("kid"));
        assertEquals("HS512", jws.getHeader("alg"));
        JwtClaims claims = JwtClaims.parse(jws.getPayload());
        assertEquals("alice", claims.getClaimValue("preferred_username"));
    }

    @Test
    void signJwkSetNoConfiguredKid() {
        assertThrows(JwtSignatureException.class,
                () -> Jwt.preferredUserName("alice").sign("/privateSigningKeys.jwks"), "JwtSignatureException is expected");
    }

    @Test
    void signJwkSetWithKid() throws Exception {
        String jwt = Jwt.preferredUserName("alice").jws().keyId("secretkey1").sign("/privateSigningKeys.jwks");
        JsonWebSignature jws = getVerifiedJws(jwt, readSecretKey("/privateKey.jwk"));
        assertEquals("secretkey1", jws.getHeader("kid"));
        assertEquals("HS256", jws.getHeader("alg"));
        JwtClaims claims = JwtClaims.parse(jws.getPayload());
        assertEquals("alice", claims.getClaimValue("preferred_username"));
    }

    @Test
    void signJwkSetWithConfiguredKid() throws Exception {
        JwtBuildConfigSource configSource = JwtSignTest.getConfigSource();
        try {
            configSource.setSigningKeyId("secretkey2");
            String jwt = Jwt.preferredUserName("alice").sign("/privateSigningKeys.jwks");
            JsonWebSignature jws = getVerifiedJws(jwt, readSecretKey("/privateKeyHS512.jwk", SignatureAlgorithm.HS512));
            assertEquals("secretkey2", jws.getHeader("kid"));
            assertEquals("HS512", jws.getHeader("alg"));
            JwtClaims claims = JwtClaims.parse(jws.getPayload());
            assertEquals("alice", claims.getClaimValue("preferred_username"));
        } finally {
            configSource.setSigningKeyId(null);
        }
    }

    @Test
    void algorithmMismatch() {
        assertThrows(JwtSignatureException.class,
                () -> Jwt.preferredUserName("alice").jws().algorithm(SignatureAlgorithm.HS256)
                        .sign("/privateKeyHS512.jwk"),
                "JwtSignatureException is expected");
    }

    private Key readSecretKey(String keyLocation) throws Exception {
        return readSecretKey(keyLocation, SignatureAlgorithm.HS256);
    }

    private Key readSecretKey(String keyLocation, SignatureAlgorithm sigAlg) throws Exception {
        return KeyUtils.readSigningKey(keyLocation, null, sigAlg);
    }

    static JsonWebSignature getVerifiedJws(String jwt, Key key) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setKey(key);
        jws.setCompactSerialization(jwt);
        assertTrue(jws.verifySignature());
        return jws;
    }
}
