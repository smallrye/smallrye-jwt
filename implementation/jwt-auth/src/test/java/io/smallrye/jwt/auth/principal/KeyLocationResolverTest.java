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

import java.net.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.jose4j.http.Get;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
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

import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.util.KeyUtils;
import io.smallrye.jwt.util.ResourceUtils;
import io.smallrye.jwt.util.ResourceUtils.UrlStreamResolver;

@RunWith(MockitoJUnitRunner.class)
public class KeyLocationResolverTest {

    @Mock
    JsonWebSignature signature;
    @Mock
    Headers headers;
    @Mock
    HttpsJwks mockedHttpsJwks;
    @Mock
    Get mockedGet;
    @Mock
    UrlStreamResolver urlResolver;

    RSAPublicKey rsaKey;
    SecretKey secretKey;

    public KeyLocationResolverTest() throws Exception {
        rsaKey = (RSAPublicKey) KeyUtils.generateKeyPair(2048).getPublic();
        secretKey = new SecretKeySpec("123456789ABCDEF".getBytes(StandardCharsets.UTF_8), "AES");
    }

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Test
    public void testLoadPemKeyWithWrongLocation() throws Exception {

        expectedEx.expect(UnresolvableKeyException.class);

        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(new JWTAuthContextInfo("wrong_location.pem", null));
        keyLocationResolver.resolveKey(signature, emptyList());
    }

    @Test
    public void testLoadRsaKeyFromHttpsJwks() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("https://github.com/my_key.jwks", "issuer");
        contextInfo.setJwksRefreshInterval(10);

        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo) {
            protected HttpsJwks getHttpsJwks(String loc) {
                return mockedHttpsJwks;
            }

            protected Get getHttpGet() {
                return mockedGet;
            }
        };
        Mockito.verify(mockedGet, Mockito.never()).setTrustedCertificates(Mockito.any(X509Certificate.class));
        Mockito.verify(mockedGet, Mockito.never()).setHostnameVerifier(Mockito.any());
        Mockito.verify(mockedHttpsJwks).setSimpleHttpGet(mockedGet);

        RsaJsonWebKey jwk = new RsaJsonWebKey(rsaKey);
        jwk.setKeyId("1");
        when(mockedHttpsJwks.getJsonWebKeys()).thenReturn(Collections.singletonList(jwk));
        keyLocationResolver = Mockito.spy(keyLocationResolver);
        when(signature.getHeaders()).thenReturn(headers);
        when(headers.getStringHeaderValue(JsonWebKey.KEY_ID_PARAMETER)).thenReturn("1");

        assertEquals(rsaKey, keyLocationResolver.resolveKey(signature, emptyList()));
        assertNull(keyLocationResolver.key);
    }

    @Test
    public void testLoadRsaKeyFromHttpsJwksWithCertAndTrustAll() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("https://github.com/my_key.jwks", "issuer");
        contextInfo.setTlsCertificate(KeyUtils.readKeyContent("publicCrt.pem"));
        contextInfo.setTlsTrustAll(true);
        contextInfo.setJwksRefreshInterval(10);

        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo) {
            protected HttpsJwks getHttpsJwks(String loc) {
                return mockedHttpsJwks;
            }

            protected Get getHttpGet() {
                return mockedGet;
            }
        };
        Mockito.verify(mockedGet).setTrustedCertificates(Mockito.any(X509Certificate.class));
        Mockito.verify(mockedGet).setHostnameVerifier(Mockito.any(AbstractKeyLocationResolver.TrustAllHostnameVerifier.class));
        Mockito.verify(mockedHttpsJwks).setSimpleHttpGet(mockedGet);

        RsaJsonWebKey jwk = new RsaJsonWebKey(rsaKey);
        jwk.setKeyId("1");
        when(mockedHttpsJwks.getJsonWebKeys()).thenReturn(Collections.singletonList(jwk));
        keyLocationResolver = Mockito.spy(keyLocationResolver);
        when(signature.getHeaders()).thenReturn(headers);
        when(headers.getStringHeaderValue(JsonWebKey.KEY_ID_PARAMETER)).thenReturn("1");

        assertEquals(rsaKey, keyLocationResolver.resolveKey(signature, emptyList()));
        assertNull(keyLocationResolver.key);
    }

    @Test
    public void testLoadRsaKeyFromHttpsJwksWithCertPathAndTrustedHostsAndProxy() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("https://github.com/my_key.jwks", "issuer");
        contextInfo.setTlsCertificatePath("publicCrt.pem");
        contextInfo.setTlsTrustedHosts(new HashSet<>(Arrays.asList("trusted-host")));
        contextInfo.setHttpProxyHost("proxyhost");
        contextInfo.setJwksRefreshInterval(10);

        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo) {
            protected HttpsJwks getHttpsJwks(String loc) {
                return mockedHttpsJwks;
            }

            protected Get getHttpGet() {
                return mockedGet;
            }
        };
        Mockito.verify(mockedGet).setTrustedCertificates(Mockito.any(X509Certificate.class));
        Mockito.verify(mockedGet)
                .setHostnameVerifier(Mockito.any(AbstractKeyLocationResolver.TrustedHostsHostnameVerifier.class));
        Mockito.verify(mockedGet).setHttpProxy(Mockito.any(Proxy.class));
        Mockito.verify(mockedHttpsJwks).setSimpleHttpGet(mockedGet);

        RsaJsonWebKey jwk = new RsaJsonWebKey(rsaKey);
        jwk.setKeyId("1");
        when(mockedHttpsJwks.getJsonWebKeys()).thenReturn(Collections.singletonList(jwk));
        keyLocationResolver = Mockito.spy(keyLocationResolver);
        when(signature.getHeaders()).thenReturn(headers);
        when(headers.getStringHeaderValue(JsonWebKey.KEY_ID_PARAMETER)).thenReturn("1");

        assertEquals(rsaKey, keyLocationResolver.resolveKey(signature, emptyList()));
        assertNull(keyLocationResolver.key);
    }

    @Test
    public void testLoadRsaKeyFromHttpJwks() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("http://github.com/my_key.jwks", "issuer");
        contextInfo.setJwksRefreshInterval(10);

        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo) {
            protected HttpsJwks initializeHttpsJwks(String loc) {
                return mockedHttpsJwks;
            }
        };
        RsaJsonWebKey jwk = new RsaJsonWebKey(rsaKey);
        jwk.setKeyId("1");
        when(mockedHttpsJwks.getJsonWebKeys()).thenReturn(Collections.singletonList(jwk));
        keyLocationResolver = Mockito.spy(keyLocationResolver);
        when(signature.getHeaders()).thenReturn(headers);
        when(headers.getStringHeaderValue(JsonWebKey.KEY_ID_PARAMETER)).thenReturn("1");

        assertEquals(rsaKey, keyLocationResolver.resolveKey(signature, emptyList()));
        assertNull(keyLocationResolver.key);
    }

    @Test
    public void testLoadSecretKeyFromHttpsJwks() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("https://github.com/my_key.jwks", "issuer");
        contextInfo.setJwksRefreshInterval(10);

        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo) {
            protected HttpsJwks initializeHttpsJwks(String loc) {
                return mockedHttpsJwks;
            }
        };
        OctetSequenceJsonWebKey jwk = new OctetSequenceJsonWebKey(secretKey);
        jwk.setKeyId("1");
        when(mockedHttpsJwks.getJsonWebKeys()).thenReturn(Collections.singletonList(jwk));
        keyLocationResolver = Mockito.spy(keyLocationResolver);
        when(signature.getHeaders()).thenReturn(headers);
        when(headers.getStringHeaderValue(JsonWebKey.KEY_ID_PARAMETER)).thenReturn("1");

        assertEquals(secretKey, keyLocationResolver.resolveKey(signature, emptyList()));
        assertNull(keyLocationResolver.key);
    }

    @Test
    public void testLoadHttpsJwksNonMathchingKidAndRefresh() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("https://github.com/my_key.jwks", "issuer");
        contextInfo.setJwksRefreshInterval(10);

        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo) {
            protected HttpsJwks initializeHttpsJwks(String loc) {
                return mockedHttpsJwks;
            }
        };
        // token 'kid' is '1'
        when(signature.getHeaders()).thenReturn(headers);
        when(headers.getStringHeaderValue(JsonWebKey.KEY_ID_PARAMETER)).thenReturn("1");

        final RsaJsonWebKey jwk = new RsaJsonWebKey(rsaKey);

        // Return JWK Set with a non-matching JWK with 'kid' set to '2' 
        jwk.setKeyId("2");
        when(mockedHttpsJwks.getJsonWebKeys()).thenReturn(Collections.singletonList(jwk));

        // Refresh JWK Set and get a matching JWK with 'kid' set to '1'
        doAnswer((i) -> {
            jwk.setKeyId("1");
            return null;
        }).when(mockedHttpsJwks).refresh();

        keyLocationResolver = Mockito.spy(keyLocationResolver);
        assertEquals(rsaKey, keyLocationResolver.resolveKey(signature, emptyList()));
        assertNull(keyLocationResolver.key);
    }

    @Test
    public void testLoadHttpJwksNonMathchingKidAndRefresh() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("http://github.com/my_key.jwks", "issuer");
        contextInfo.setJwksRefreshInterval(10);

        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo) {
            protected HttpsJwks initializeHttpsJwks(String loc) {
                return mockedHttpsJwks;
            }
        };
        // token 'kid' is '1'
        when(signature.getHeaders()).thenReturn(headers);
        when(headers.getStringHeaderValue(JsonWebKey.KEY_ID_PARAMETER)).thenReturn("1");

        final RsaJsonWebKey jwk = new RsaJsonWebKey(rsaKey);

        // Return JWK Set with a non-matching JWK with 'kid' set to '2' 
        jwk.setKeyId("2");
        when(mockedHttpsJwks.getJsonWebKeys()).thenReturn(Collections.singletonList(jwk));

        // Refresh JWK Set and get a matching JWK with 'kid' set to '1'
        doAnswer((i) -> {
            jwk.setKeyId("1");
            return null;
        }).when(mockedHttpsJwks).refresh();

        keyLocationResolver = Mockito.spy(keyLocationResolver);
        assertEquals(rsaKey, keyLocationResolver.resolveKey(signature, emptyList()));
        assertNull(keyLocationResolver.key);
    }

    @Test(expected = UnresolvableKeyException.class)
    public void testLoadHttpsJwksNonMathchingKidAndRefreshDeclined() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("https://github.com/my_key.jwks", "issuer");
        contextInfo.setJwksRefreshInterval(10);
        contextInfo.setForcedJwksRefreshInterval(10);

        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo) {
            protected HttpsJwks initializeHttpsJwks(String loc) {
                return mockedHttpsJwks;
            }
        };
        // token 'kid' is '1'
        when(signature.getHeaders()).thenReturn(headers);
        when(headers.getStringHeaderValue(JsonWebKey.KEY_ID_PARAMETER)).thenReturn("1");

        final RsaJsonWebKey jwk = new RsaJsonWebKey(rsaKey);

        // Return JWK Set with a non-matching JWK with 'kid' set to '2' 
        jwk.setKeyId("2");
        when(mockedHttpsJwks.getJsonWebKeys()).thenReturn(Collections.singletonList(jwk));

        // Refresh JWK Set and get a matching JWK with 'kid' set to '1'
        doAnswer((i) -> {
            jwk.setKeyId("1");
            return null;
        }).when(mockedHttpsJwks).refresh();

        keyLocationResolver = Mockito.spy(keyLocationResolver);
        assertEquals(rsaKey, keyLocationResolver.resolveKey(signature, emptyList()));
        assertNull(keyLocationResolver.key);

        // Return JWK Set with a non-matching JWK with 'kid' set to '2'
        jwk.setKeyId("2");
        keyLocationResolver.resolveKey(signature, emptyList());
    }

    @Test
    public void testLoadHttpsPemCrt() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("https://github.com/my_key.crt", "issuer");
        contextInfo.setJwksRefreshInterval(10);

        Mockito.doThrow(new JoseException("")).when(mockedHttpsJwks).refresh();
        Mockito.doReturn(ResourceUtils.getAsClasspathResource("publicCrt.pem"))
                .when(urlResolver).resolve(Mockito.any());
        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo) {
            protected HttpsJwks initializeHttpsJwks(String loc) {
                return mockedHttpsJwks;
            }

            protected UrlStreamResolver getUrlResolver() {
                return urlResolver;
            }
        };
        assertNotNull(keyLocationResolver.key);
        assertEquals(keyLocationResolver.key, keyLocationResolver.resolveKey(signature, emptyList()));
        assertEquals(keyLocationResolver.key,
                keyLocationResolver.tryAsPEMCertificate(keyLocationResolver.readKeyContent("publicCrt.pem")));
    }

    @Test
    public void testLoadPemCertOnClassPath() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("publicCrt.pem", "issuer");
        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo);
        assertNotNull(keyLocationResolver.key);
        assertEquals(keyLocationResolver.key, keyLocationResolver.resolveKey(signature, emptyList()));
        assertEquals(keyLocationResolver.key,
                keyLocationResolver.tryAsPEMCertificate(keyLocationResolver.readKeyContent("publicCrt.pem")));
    }

    @Test
    public void testLoadPemOnClassPath() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("publicKey.pem", "issuer");
        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo);
        assertNotNull(keyLocationResolver.key);
        assertEquals(keyLocationResolver.key, keyLocationResolver.resolveKey(signature, emptyList()));
        assertEquals(keyLocationResolver.key,
                KeyLocationResolver.tryAsPEMPublicKey(keyLocationResolver.readKeyContent("publicKey.pem"),
                        SignatureAlgorithm.RS256));
    }

    @Test
    public void testLoadJWKOnClassPath() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("publicKey.jwk", "issuer");
        contextInfo.setTokenKeyId("key1");
        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo);
        when(signature.getHeaders()).thenReturn(headers);
        when(headers.getStringHeaderValue(JsonWebKey.KEY_ID_PARAMETER)).thenReturn("key1");
        assertNotNull(keyLocationResolver.key);
        assertEquals(keyLocationResolver.key, keyLocationResolver.resolveKey(signature, emptyList()));
        assertEquals(keyLocationResolver.key,
                keyLocationResolver.getJsonWebKey("key1", null).getKey());
    }
}
