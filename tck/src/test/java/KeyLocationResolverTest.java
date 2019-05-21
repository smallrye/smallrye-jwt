/*
 *
 *   Copyright 2018 Red Hat, Inc, and individual contributors.
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


import java.security.PrivateKey;

import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.jose4j.lang.UnresolvableKeyException;
import org.testng.Assert;
import org.testng.annotations.Test;

import io.smallrye.jwt.auth.principal.DefaultJWTTokenParser;
import io.smallrye.jwt.auth.principal.ParseException;
import io.smallrye.jwt.config.JWTAuthContextInfoProvider;

public class KeyLocationResolverTest {
    @Test
    public void testLoadJwkKeyWithMatchingKid() throws Exception {
        verifyTokenWithJwkKey("key1", "publicKey.jwk");
    }
    @Test
    public void testLoadJwkKeyWithNonMatchingKid() throws Exception {
        try {
            verifyTokenWithJwkKey("key2", "publicKey.jwk");
            Assert.fail("ParseException is expected");
        } catch (ParseException ex) {
            Assert.assertTrue(ex.getCause().getCause() instanceof UnresolvableKeyException);
        }
    }
    
    @Test
    public void testLoadJwkKeyWithMatchingKidFromSet() throws Exception {
        verifyTokenWithJwkKey("key1", "publicKeySet.jwk");
    }
    @Test
    public void testLoadJwkKeyWithNonMatchingKidFromSet() throws Exception {
        try {
            verifyTokenWithJwkKey("key3", "publicKeySet.jwk");
            Assert.fail("ParseException is expected");
        } catch (ParseException ex) {
            Assert.assertTrue(ex.getCause().getCause() instanceof UnresolvableKeyException);
        }
    }

    private static void verifyTokenWithJwkKey(String kid, String jwkResource) throws Exception {
        PrivateKey privateKey = TokenUtils.readPrivateKey("/privateKey.pem");
        String token = TokenUtils.generateTokenString(privateKey, kid, "/Token1.json", null, null);
        JWTAuthContextInfoProvider provider = new JWTAuthContextInfoProvider("NONE", jwkResource, "https://server.example.com");
        Assert.assertNotNull(new DefaultJWTTokenParser().parse(token, provider.getContextInfo()));
    }
}
