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

import static org.junit.Assert.assertThrows;

import java.security.Key;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.junit.Assert;
import org.junit.Test;

import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.util.KeyUtils;

public class JwtSignJwkTest {

    @Test
    public void testSignHS256() throws Exception {
        String jwt = Jwt.preferredUserName("alice").sign("/privateKey.jwk");
        JsonWebSignature jws = getVerifiedJws(jwt, readSecretKey("/privateKey.jwk"));
        Assert.assertEquals("secretkey1", jws.getHeader("kid"));
        // HS256 is a default value
        Assert.assertEquals("HS256", jws.getHeader("alg"));
        JwtClaims claims = JwtClaims.parse(jws.getPayload());
        Assert.assertEquals("alice", claims.getClaimValue("preferred_username"));

    }

    @Test
    public void testSignHS512() throws Exception {
        String jwt = Jwt.preferredUserName("alice").sign("/privateKeyHS512.jwk");
        JsonWebSignature jws = getVerifiedJws(jwt, readSecretKey("/privateKeyHS512.jwk", SignatureAlgorithm.HS512));
        Assert.assertEquals("secretkey2", jws.getHeader("kid"));
        Assert.assertEquals("HS512", jws.getHeader("alg"));
        JwtClaims claims = JwtClaims.parse(jws.getPayload());
        Assert.assertEquals("alice", claims.getClaimValue("preferred_username"));
    }

    @Test
    public void testAlgorithmMismatch() throws Exception {
        assertThrows("JwtSignatureException is expected", JwtSignatureException.class,
                () -> Jwt.preferredUserName("alice").jws().algorithm(SignatureAlgorithm.HS256)
                        .sign("/privateKeyHS512.jwk"));
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
        Assert.assertTrue(jws.verifySignature());
        return jws;
    }
}
