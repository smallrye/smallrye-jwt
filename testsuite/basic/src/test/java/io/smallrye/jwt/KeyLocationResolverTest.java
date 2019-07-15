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

package io.smallrye.jwt;

import java.security.PrivateKey;

import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.jose4j.lang.UnresolvableKeyException;
import org.testng.Assert;
import org.testng.annotations.Test;

import io.smallrye.jwt.auth.principal.DefaultJWTTokenParser;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.ParseException;
import io.smallrye.jwt.config.JWTAuthContextInfoProvider;

public class KeyLocationResolverTest {
    @Test
    public void testVerifyWithJwkKeyWithMatchingKid() throws Exception {
        verifyToken("key1", null, "publicKey.jwk");
    }

    @Test
    public void testVerifyWithJwkKeyWithNonMatchingKid() throws Exception {
        try {
            verifyToken("key2", null, "publicKey.jwk");
            Assert.fail("ParseException is expected");
        } catch (ParseException ex) {
            Assert.assertTrue(ex.getCause().getCause() instanceof UnresolvableKeyException);
        }
    }

    @Test
    public void testVerifyWithJwkKeyWithMatchingKidFromSet() throws Exception {
        verifyToken("key1", null, "publicKeySet.jwk");
    }

    @Test
    public void testVerifyWithJwkFromSetWithKidAndRequiredKid() throws Exception {
        verifyToken("key1", "key1", "publicKeySet.jwk");
    }

    @Test
    public void testVerifyWithJwkFromSetWithWrongKidAndRequiredKid() throws Exception {
        try {
            verifyToken("key2", "key1", "publicKeySet.jwk");
            Assert.fail("ParseException is expected");
        } catch (ParseException ex) {
            Assert.assertTrue(ex.getCause().getCause() instanceof UnresolvableKeyException);
        }
    }

    @Test
    public void testVerifyWithJwkKeyWithNonMatchingKidFromSet() throws Exception {
        try {
            verifyToken("key3", null, "publicKeySet.jwk");
            Assert.fail("ParseException is expected");
        } catch (ParseException ex) {
            Assert.assertTrue(ex.getCause().getCause() instanceof UnresolvableKeyException);
        }
    }

    @Test
    public void testVerifyWithClassPathPemKey() throws Exception {
        verifyToken("key3", null, "publicKey.pem");
    }

    @Test
    public void testVerifyWithClassPathPemKey2() throws Exception {
        verifyToken("key3", null, "classpath:publicKey.pem");
    }

    @Test
    public void testVerifyWithFileSystemPemKey() throws Exception {
        verifyToken("key3", null, "target/test-classes/publicKey.pem");
    }

    @Test
    public void testVerifyWithFileSystemPemKey2() throws Exception {
        verifyToken("key3", null, "file:target/test-classes/publicKey.pem");
    }

    private static void verifyToken(String kid, String requiredKeyId, String publicKeyLocation) throws Exception {
        PrivateKey privateKey = TokenUtils.readPrivateKey("/privateKey.pem");
        String token = TokenUtils.generateTokenString(privateKey, kid, "/Token1.json", null, null);
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider.createWithKeyLocation(publicKeyLocation,
                "https://server.example.com");
        JWTAuthContextInfo contextInfo = provider.getContextInfo();
        contextInfo.setTokenKeyId(requiredKeyId);
        Assert.assertNotNull(new DefaultJWTTokenParser().parse(token, contextInfo));
    }

}
