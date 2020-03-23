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

package io.smallrye.jwt.auth.principal;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Base64;

import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.testng.Assert;
import org.testng.annotations.Test;

import io.smallrye.jwt.config.JWTAuthContextInfoProvider;
import io.smallrye.jwt.util.KeyUtils;

public class KeyLocationResolverKeyContentTest {
    @Test
    public void testVerifyWithPemKey() throws Exception {
        verifyToken(null, KeyUtils.removePemKeyBeginEnd(readKeyContent("/publicKey.pem")));
    }

    @Test
    public void testVerifyWithJwkKey() throws Exception {
        verifyToken(null,
                Base64.getUrlEncoder().encodeToString(readKeyContent("/publicKey.jwk").getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void testVerifyWithJwkKeySet() throws Exception {
        verifyToken("key1",
                Base64.getUrlEncoder().encodeToString(readKeyContent("/publicKeySet.jwk").getBytes(StandardCharsets.UTF_8)));
    }

    private void verifyToken(String kid, String publicKey) throws Exception {
        PrivateKey privateKey = TokenUtils.readPrivateKey("/privateKey.pem");
        String token = TokenUtils.signClaims(privateKey, kid, "/Token1.json", null, null);
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider.createWithKey(publicKey,
                "https://server.example.com");
        JWTAuthContextInfo contextInfo = provider.getContextInfo();
        Assert.assertNotNull(new DefaultJWTTokenParser().parse(token, contextInfo));
    }

    private String readKeyContent(String keyLocation) throws Exception {
        InputStream is = KeyUtils.class.getResourceAsStream(keyLocation);
        StringWriter contents = new StringWriter();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
            String line = null;
            while ((line = reader.readLine()) != null) {
                contents.write(line);
            }
        }
        return contents.toString();
    }
}
