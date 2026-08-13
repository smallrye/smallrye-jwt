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

import java.security.Key;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.AESDecrypter;
import com.nimbusds.jwt.JWTClaimsSet;

import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.jwt.util.KeyUtils;

class JwtEncryptJwkTest {
    @Test
    void encryptA256KW() throws Exception {
        String jwt = Jwt.preferredUserName("alice").jwe().encrypt("/privateKey.jwk");
        JWEObject jwe = getDecryptedJwe(jwt, readSecretKey("/privateKey.jwk"));
        assertEquals("secretkey1", jwe.getHeader().getKeyID());
        // A256KW is a default value
        assertEquals("A256KW", jwe.getHeader().getAlgorithm().getName());
        JWTClaimsSet claims = JWTClaimsSet.parse(jwe.getPayload().toString());
        assertEquals("alice", claims.getClaim("preferred_username"));

    }

    @Test
    void encryptA128KW() throws Exception {
        String jwt = Jwt.preferredUserName("alice").jwe().encrypt("/privateKeyA128KW.jwk");
        JWEObject jwe = getDecryptedJwe(jwt,
                readSecretKey("/privateKeyA128KW.jwk", KeyEncryptionAlgorithm.A128KW));
        assertEquals("secretkey3", jwe.getHeader().getKeyID());
        assertEquals("A128KW", jwe.getHeader().getAlgorithm().getName());
        JWTClaimsSet claims = JWTClaimsSet.parse(jwe.getPayload().toString());
        assertEquals("alice", claims.getClaim("preferred_username"));
    }

    @Test
    void algorithmMismatch() {
        assertThrows(JwtEncryptionException.class,
                () -> Jwt.preferredUserName("alice").jwe().keyAlgorithm(KeyEncryptionAlgorithm.A256KW)
                        .encrypt("/privateKeyA128KW.jwk"),
                "JwtEncryptionException is expected");
    }

    @Test
    void encryptJwkSetNoConfiguredKid() {
        assertThrows(JwtEncryptionException.class,
                () -> Jwt.preferredUserName("alice").jwe().encrypt("/privateEncryptionKeys.jwks"),
                "JwtEncryptionException is expected");
    }

    @Test
    void signJwkSetWithKid() throws Exception {
        String jwt = Jwt.preferredUserName("alice").jwe().keyId("secretkey1").encrypt("/privateEncryptionKeys.jwks");
        JWEObject jwe = getDecryptedJwe(jwt, readSecretKey("/privateKey.jwk"));
        assertEquals("secretkey1", jwe.getHeader().getKeyID());
        // A256KW is a default value
        assertEquals("A256KW", jwe.getHeader().getAlgorithm().getName());
        JWTClaimsSet claims = JWTClaimsSet.parse(jwe.getPayload().toString());
        assertEquals("alice", claims.getClaim("preferred_username"));
    }

    @Test
    void signJwkSetWithConfiguredKid() throws Exception {
        JwtBuildConfigSource configSource = JwtSignTest.getConfigSource();
        try {
            configSource.setEncryptonKeyId("secretkey3");
            String jwt = Jwt.preferredUserName("alice").jwe().encrypt("/privateEncryptionKeys.jwks");
            JWEObject jwe = getDecryptedJwe(jwt,
                    readSecretKey("/privateKeyA128KW.jwk", KeyEncryptionAlgorithm.A128KW));
            assertEquals("secretkey3", jwe.getHeader().getKeyID());
            assertEquals("A128KW", jwe.getHeader().getAlgorithm().getName());
            JWTClaimsSet claims = JWTClaimsSet.parse(jwe.getPayload().toString());
            assertEquals("alice", claims.getClaim("preferred_username"));
        } finally {
            configSource.setEncryptonKeyId(null);
        }
    }

    private Key readSecretKey(String keyLocation) throws Exception {
        return readSecretKey(keyLocation, KeyEncryptionAlgorithm.A256KW);
    }

    private Key readSecretKey(String keyLocation, KeyEncryptionAlgorithm keyAlg) throws Exception {
        return KeyUtils.readEncryptionKey(keyLocation, null, keyAlg);
    }

    private static JWEObject getDecryptedJwe(String compactJwe, Key decryptionKey) throws Exception {
        JWEObject jwe = JWEObject.parse(compactJwe);
        jwe.decrypt(new AESDecrypter((SecretKey) decryptionKey));
        return jwe;
    }
}
