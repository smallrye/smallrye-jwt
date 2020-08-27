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

import static java.util.Collections.emptyList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.Collections;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jwx.Headers;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.UnresolvableKeyException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import io.smallrye.jwt.ResourceUtils;
import io.smallrye.jwt.ResourceUtils.UrlStreamResolver;

@RunWith(MockitoJUnitRunner.class)
public class DecryptionKeyLocationResolverTest {

    @Mock
    JsonWebEncryption encryption;
    @Mock
    Headers headers;
    @Mock
    HttpsJwks mockedHttpsJwks;
    @Mock
    UrlStreamResolver urlResolver;

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Test
    public void testLoadPemKeyWithWrongLocation() throws Exception {

        expectedEx.expect(UnresolvableKeyException.class);

        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();
        contextInfo.setDecryptionKeyLocation("wrong_location.pem");
        new DecryptionKeyLocationResolver(contextInfo).resolveKey(encryption, emptyList());
    }

    @Test
    public void testLoadRsaKeyFromHttpsJwks() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();
        contextInfo.setDecryptionKeyLocation("https://github.com/my_key.jwks");
        contextInfo.setJwksRefreshInterval(10);

        DecryptionKeyLocationResolver keyLocationResolver = new DecryptionKeyLocationResolver(contextInfo) {
            protected HttpsJwks initializeHttpsJwks(String loc) {
                return mockedHttpsJwks;
            }
        };
        RsaJsonWebKey jwk = RsaJwkGenerator.generateJwk(2048);
        jwk.setKeyId("1");
        when(mockedHttpsJwks.getJsonWebKeys()).thenReturn(Collections.singletonList(jwk));
        keyLocationResolver = Mockito.spy(keyLocationResolver);
        when(encryption.getHeaders()).thenReturn(headers);
        when(headers.getStringHeaderValue(JsonWebKey.KEY_ID_PARAMETER)).thenReturn("1");

        assertEquals(jwk.getPrivateKey(), keyLocationResolver.resolveKey(encryption, emptyList()));
        assertNull(keyLocationResolver.key);
    }

    @Test
    public void testLoadSecretKeyFromHttpsJwks() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();
        contextInfo.setDecryptionKeyLocation("https://github.com/my_key.jwks");
        contextInfo.setJwksRefreshInterval(10);

        DecryptionKeyLocationResolver keyLocationResolver = new DecryptionKeyLocationResolver(contextInfo) {
            protected HttpsJwks initializeHttpsJwks(String loc) {
                return mockedHttpsJwks;
            }
        };
        SecretKey secretKey = new SecretKeySpec("123456789ABCDEF".getBytes(StandardCharsets.UTF_8), "AES");
        OctetSequenceJsonWebKey jwk = new OctetSequenceJsonWebKey(secretKey);
        jwk.setKeyId("1");
        when(mockedHttpsJwks.getJsonWebKeys()).thenReturn(Collections.singletonList(jwk));
        keyLocationResolver = Mockito.spy(keyLocationResolver);
        when(encryption.getHeaders()).thenReturn(headers);
        when(headers.getStringHeaderValue(JsonWebKey.KEY_ID_PARAMETER)).thenReturn("1");

        assertEquals(secretKey, keyLocationResolver.resolveKey(encryption, emptyList()));
        assertNull(keyLocationResolver.key);
    }

    @Test
    public void testLoadHttpsJwksNonMathchingKidAndRefresh() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();
        contextInfo.setDecryptionKeyLocation("https://github.com/my_key.jwks");
        contextInfo.setJwksRefreshInterval(10);

        DecryptionKeyLocationResolver keyLocationResolver = new DecryptionKeyLocationResolver(contextInfo) {
            protected HttpsJwks initializeHttpsJwks(String loc) {
                return mockedHttpsJwks;
            }
        };
        // token 'kid' is '1'
        when(encryption.getHeaders()).thenReturn(headers);
        when(headers.getStringHeaderValue(JsonWebKey.KEY_ID_PARAMETER)).thenReturn("1");

        RsaJsonWebKey jwk = RsaJwkGenerator.generateJwk(2048);

        // Return JWK Set with a non-matching JWK with 'kid' set to '2' 
        jwk.setKeyId("2");
        when(mockedHttpsJwks.getJsonWebKeys()).thenReturn(Collections.singletonList(jwk));

        // Refresh JWK Set and get a matching JWK with 'kid' set to '1'
        doAnswer((i) -> {
            jwk.setKeyId("1");
            return null;
        }).when(mockedHttpsJwks).refresh();

        keyLocationResolver = Mockito.spy(keyLocationResolver);
        assertEquals(jwk.getPrivateKey(), keyLocationResolver.resolveKey(encryption, emptyList()));
        assertNull(keyLocationResolver.key);
    }

    @Test(expected = UnresolvableKeyException.class)
    public void testLoadHttpsJwksNonMathchingKidAndRefreshDeclined() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();
        contextInfo.setDecryptionKeyLocation("https://github.com/my_key.jwks");
        contextInfo.setJwksRefreshInterval(10);
        contextInfo.setForcedJwksRefreshInterval(10);

        DecryptionKeyLocationResolver keyLocationResolver = new DecryptionKeyLocationResolver(contextInfo) {
            protected HttpsJwks initializeHttpsJwks(String loc) {
                return mockedHttpsJwks;
            }
        };
        // token 'kid' is '1'
        when(encryption.getHeaders()).thenReturn(headers);
        when(headers.getStringHeaderValue(JsonWebKey.KEY_ID_PARAMETER)).thenReturn("1");

        RsaJsonWebKey jwk = RsaJwkGenerator.generateJwk(2048);

        // Return JWK Set with a non-matching JWK with 'kid' set to '2' 
        jwk.setKeyId("2");
        when(mockedHttpsJwks.getJsonWebKeys()).thenReturn(Collections.singletonList(jwk));

        // Refresh JWK Set and get a matching JWK with 'kid' set to '1'
        doAnswer((i) -> {
            jwk.setKeyId("1");
            return null;
        }).when(mockedHttpsJwks).refresh();

        keyLocationResolver = Mockito.spy(keyLocationResolver);
        assertEquals(jwk.getPrivateKey(), keyLocationResolver.resolveKey(encryption, emptyList()));
        assertNull(keyLocationResolver.key);

        // Return JWK Set with a non-matching JWK with 'kid' set to '2'
        jwk.setKeyId("2");
        keyLocationResolver.resolveKey(encryption, emptyList());
    }

    @Test
    public void testLoadHttpsPem() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();
        contextInfo.setDecryptionKeyLocation("https://github.com/my_key.pem");
        contextInfo.setJwksRefreshInterval(10);

        Mockito.doThrow(new JoseException("")).when(mockedHttpsJwks).refresh();
        Mockito.doReturn(ResourceUtils.getAsClasspathResource("privateKey.pem"))
                .when(urlResolver).resolve(Mockito.any());
        DecryptionKeyLocationResolver keyLocationResolver = new DecryptionKeyLocationResolver(contextInfo) {
            protected HttpsJwks initializeHttpsJwks(String loc) {
                return mockedHttpsJwks;
            }

            protected UrlStreamResolver getUrlResolver() {
                return urlResolver;
            }
        };
        assertNotNull(keyLocationResolver.key);
        assertEquals(keyLocationResolver.key, keyLocationResolver.resolveKey(encryption, emptyList()));
        assertEquals(keyLocationResolver.key,
                DecryptionKeyLocationResolver.tryAsPEMPrivateKey(keyLocationResolver.readKeyContent("privateKey.pem")));
    }

    @Test
    public void testLoadPemOnClassPath() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();
        contextInfo.setDecryptionKeyLocation("privateKey.pem");
        DecryptionKeyLocationResolver keyLocationResolver = new DecryptionKeyLocationResolver(contextInfo);
        assertNotNull(keyLocationResolver.key);
        assertEquals(keyLocationResolver.key, keyLocationResolver.resolveKey(encryption, emptyList()));
        assertEquals(keyLocationResolver.key,
                DecryptionKeyLocationResolver.tryAsPEMPrivateKey(keyLocationResolver.readKeyContent("privateKey.pem")));
    }

    @Test
    public void testLoadJWKOnClassPath() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();
        contextInfo.setDecryptionKeyLocation("decryptPrivateKey.jwk");
        contextInfo.setTokenDecryptionKeyId("key1");
        when(encryption.getHeaders()).thenReturn(headers);
        when(headers.getStringHeaderValue(JsonWebKey.KEY_ID_PARAMETER)).thenReturn("key1");
        DecryptionKeyLocationResolver keyLocationResolver = new DecryptionKeyLocationResolver(contextInfo);
        assertNotNull(keyLocationResolver.key);
        assertEquals(keyLocationResolver.key, keyLocationResolver.resolveKey(encryption, emptyList()));
        assertEquals(keyLocationResolver.key,
                ((PublicJsonWebKey) keyLocationResolver.getJsonWebKey("key1", null)).getPrivateKey());
    }
}
