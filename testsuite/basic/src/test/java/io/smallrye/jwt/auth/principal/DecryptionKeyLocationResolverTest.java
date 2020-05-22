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

import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.testng.Assert;
import org.testng.annotations.Test;

import io.smallrye.jwt.config.JWTAuthContextInfoProvider;

public class DecryptionKeyLocationResolverTest {

    @Test
    public void testDecryptVerifyTokenWithPemKey() throws Exception {
        String token = TokenUtils.signEncryptClaims("/Token1.json");
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider
                .createWithVerifyDecryptKeyLocations("publicKey.pem", "privateKey.pem",
                        "https://server.example.com");
        JWTAuthContextInfo contextInfo = provider.getContextInfo();
        Assert.assertNotNull(new DefaultJWTTokenParser().parse(token, contextInfo));
    }

    @Test
    public void testDecryptTokenWithPemKey() throws Exception {
        String token = TokenUtils.encryptClaims("/Token1.json");
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider
                .createWithDecryptKeyLocation("privateKey.pem", "https://server.example.com");
        JWTAuthContextInfo contextInfo = provider.getContextInfo();
        Assert.assertNotNull(new DefaultJWTTokenParser().parse(token, contextInfo));
    }
}
