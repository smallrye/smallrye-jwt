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

import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwt.JwtClaims;
import org.junit.Assert;
import org.junit.Test;

import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.jwt.util.KeyUtils;

public class JwtEncryptJwkTest {

    @Test
    public void testEncryptA256KW() throws Exception {
        String jwt = Jwt.preferredUserName("alice").jwe().encrypt("/privateKey.jwk");
        JsonWebEncryption jwe = getJsonWebEncryption(jwt, readSecretKey("/privateKey.jwk"));
        Assert.assertEquals("secretkey1", jwe.getHeader("kid"));
        // HS256 is a default value
        Assert.assertEquals("A256KW", jwe.getHeader("alg"));
        JwtClaims claims = JwtClaims.parse(jwe.getPayload());
        Assert.assertEquals("alice", claims.getClaimValue("preferred_username"));

    }

    @Test
    public void testEncryptA128KW() throws Exception {
        String jwt = Jwt.preferredUserName("alice").jwe().encrypt("/privateKeyA128KW.jwk");
        JsonWebEncryption jwe = getJsonWebEncryption(jwt,
                readSecretKey("/privateKeyA128KW.jwk", KeyEncryptionAlgorithm.A128KW));
        Assert.assertEquals("secretkey3", jwe.getHeader("kid"));
        Assert.assertEquals("A128KW", jwe.getHeader("alg"));
        JwtClaims claims = JwtClaims.parse(jwe.getPayload());
        Assert.assertEquals("alice", claims.getClaimValue("preferred_username"));
    }

    @Test
    public void testAlgorithmMismatch() throws Exception {
        assertThrows("JwtEncryptionException is expected", JwtEncryptionException.class,
                () -> Jwt.preferredUserName("alice").jwe().keyAlgorithm(KeyEncryptionAlgorithm.A256KW)
                        .encrypt("/privateKeyA128KW.jwk"));
    }

    private Key readSecretKey(String keyLocation) throws Exception {
        return readSecretKey(keyLocation, KeyEncryptionAlgorithm.A256KW);
    }

    private Key readSecretKey(String keyLocation, KeyEncryptionAlgorithm keyAlg) throws Exception {
        return KeyUtils.readEncryptionKey(keyLocation, null, keyAlg);
    }

    private static JsonWebEncryption getJsonWebEncryption(String compactJwe, Key decryptionKey) throws Exception {
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setCompactSerialization(compactJwe);
        jwe.setKey(decryptionKey);
        return jwe;
    }
}
