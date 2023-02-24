/*
 *   Copyright 2022 Red Hat, Inc, and individual contributors.
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
package io.smallrye.jwt.auth.principal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Optional;

import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;

import io.smallrye.jwt.config.JWTAuthContextInfoProvider;
import io.smallrye.jwt.util.KeyUtils;

class KeyStoreLocationTest {
    @Test
    void verifyToken() throws Exception {
        KeyStore keyStore = KeyUtils.loadKeyStore("server-keystore.jks", "password", Optional.empty(), Optional.empty());
        PrivateKey signingKey = (PrivateKey) keyStore.getKey("server", "password".toCharArray());
        String jwt = TokenUtils.signClaims(signingKey, null, "/Token1.json");

        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider.createWithKeyStoreLocation("server-keystore.jks",
                Optional.of("password"), Optional.of("server"), Optional.empty(),
                "https://server.example.com");
        JwtClaims claims = new DefaultJWTTokenParser().parse(jwt, provider.getContextInfo()).getJwtClaims();
        assertNotNull(claims);
        assertEquals("https://server.example.com", claims.getIssuer());
    }

    @Test
    void decryptToken() throws Exception {
        KeyStore keyStore = KeyUtils.loadKeyStore("server-keystore.jks", "password", Optional.empty(), Optional.empty());
        PublicKey encryptionKey = keyStore.getCertificate("server").getPublicKey();
        String jwt = TokenUtils.encryptClaims(encryptionKey, null, "/Token1.json");

        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider.createWithKeyStoreLocation("server-keystore.jks",
                Optional.of("password"), Optional.empty(), Optional.of("server"),
                "https://server.example.com");
        JwtClaims claims = new DefaultJWTTokenParser().parse(jwt, provider.getContextInfo()).getJwtClaims();
        assertNotNull(claims);
        assertEquals("https://server.example.com", claims.getIssuer());
    }
}
