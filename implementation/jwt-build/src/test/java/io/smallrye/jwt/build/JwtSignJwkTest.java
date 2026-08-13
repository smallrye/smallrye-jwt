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

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.util.KeyUtils;

class JwtSignJwkTest {
    @Test
    void signHS256() throws Exception {
        String jwt = Jwt.preferredUserName("alice").sign("/privateKey.jwk");
        SignedJWT signedJWT = getVerifiedJws(jwt, readSecretKey("/privateKey.jwk"));
        assertEquals("secretkey1", signedJWT.getHeader().getKeyID());
        // HS256 is a default value
        assertEquals("HS256", signedJWT.getHeader().getAlgorithm().getName());
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
        assertEquals("alice", claims.getClaim("preferred_username"));

    }

    @Test
    void signHS512() throws Exception {
        String jwt = Jwt.preferredUserName("alice").sign("/privateKeyHS512.jwk");
        SignedJWT signedJWT = getVerifiedJws(jwt, readSecretKey("/privateKeyHS512.jwk", SignatureAlgorithm.HS512));
        assertEquals("secretkey2", signedJWT.getHeader().getKeyID());
        assertEquals("HS512", signedJWT.getHeader().getAlgorithm().getName());
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
        assertEquals("alice", claims.getClaim("preferred_username"));
    }

    @Test
    void signJwkSetNoConfiguredKid() {
        assertThrows(JwtSignatureException.class,
                () -> Jwt.preferredUserName("alice").sign("/privateSigningKeys.jwks"), "JwtSignatureException is expected");
    }

    @Test
    void signJwkSetWithKid() throws Exception {
        String jwt = Jwt.preferredUserName("alice").jws().keyId("secretkey1").sign("/privateSigningKeys.jwks");
        SignedJWT signedJWT = getVerifiedJws(jwt, readSecretKey("/privateKey.jwk"));
        assertEquals("secretkey1", signedJWT.getHeader().getKeyID());
        assertEquals("HS256", signedJWT.getHeader().getAlgorithm().getName());
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
        assertEquals("alice", claims.getClaim("preferred_username"));
    }

    @Test
    void signJwkSetWithConfiguredKid() throws Exception {
        JwtBuildConfigSource configSource = JwtSignTest.getConfigSource();
        try {
            configSource.setSigningKeyId("secretkey2");
            String jwt = Jwt.preferredUserName("alice").sign("/privateSigningKeys.jwks");
            SignedJWT signedJWT = getVerifiedJws(jwt, readSecretKey("/privateKeyHS512.jwk", SignatureAlgorithm.HS512));
            assertEquals("secretkey2", signedJWT.getHeader().getKeyID());
            assertEquals("HS512", signedJWT.getHeader().getAlgorithm().getName());
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            assertEquals("alice", claims.getClaim("preferred_username"));
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

    static SignedJWT getVerifiedJws(String jwt, Key key) throws Exception {
        SignedJWT signedJWT = SignedJWT.parse(jwt);
        JWSVerifier verifier = createVerifier(key);
        assertTrue(signedJWT.verify(verifier));
        return signedJWT;
    }

    private static JWSVerifier createVerifier(Key key) throws JOSEException {
        if (key instanceof SecretKey) {
            return new MACVerifier((SecretKey) key);
        }
        throw new JOSEException("Unsupported key type for verification: " + key.getClass().getName());
    }
}
