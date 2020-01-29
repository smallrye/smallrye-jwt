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
import static org.mockito.Mockito.when;

import java.security.PublicKey;

import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwk.JsonWebKey;
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
import io.smallrye.jwt.auth.principal.KeyLocationResolver.UrlStreamResolver;

@RunWith(MockitoJUnitRunner.class)
public class KeyLocationResolverTest {

    @Mock
    JsonWebSignature jsonWebSignature;
    @Mock
    JsonWebSignature signature;
    @Mock
    PublicKey key;
    @Mock
    Headers headers;
    @Mock
    HttpsJwks httpsJwks;
    @Mock
    UrlStreamResolver urlResolver;

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Test
    public void testLoadPemKeyWithWrongLocation() throws Exception {

        expectedEx.expect(UnresolvableKeyException.class);

        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(new JWTAuthContextInfo("wrong_location.pem", null));
        keyLocationResolver.resolveKey(jsonWebSignature, emptyList());
    }

    @Test
    public void testLoadHttpsJwks() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("https://github.com/my_key.jwks", "issuer");
        contextInfo.setJwksRefreshInterval(10);

        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo) {
            protected HttpsJwks initializeHttpsJwks() {
                return httpsJwks;
            }
        };
        keyLocationResolver = Mockito.spy(keyLocationResolver);
        Mockito.doReturn(key).when(keyLocationResolver).getHttpsJwk(Mockito.any());
        when(signature.getHeaders()).thenReturn(headers);
        when(headers.getStringHeaderValue(JsonWebKey.KEY_ID_PARAMETER)).thenReturn("1");
        assertEquals(key, keyLocationResolver.resolveKey(signature, emptyList()));
        assertNull(keyLocationResolver.verificationKey);
    }

    @Test
    public void testLoadHttpsPemCrt() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("https://github.com/my_key.crt", "issuer");
        contextInfo.setJwksRefreshInterval(10);

        Mockito.doThrow(new JoseException("")).when(httpsJwks).refresh();
        Mockito.doReturn(KeyLocationResolver.getAsClasspathResource("publicCrt.pem"))
                .when(urlResolver).resolve(Mockito.any());
        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo) {
            protected HttpsJwks initializeHttpsJwks() {
                return httpsJwks;
            }

            protected UrlStreamResolver getUrlResolver() {
                return urlResolver;
            }
        };
        assertNotNull(keyLocationResolver.verificationKey);
        assertEquals(keyLocationResolver.verificationKey, keyLocationResolver.resolveKey(signature, emptyList()));
        assertEquals(keyLocationResolver.verificationKey,
                KeyLocationResolver.tryAsPEMCertificate(keyLocationResolver.readKeyContent("publicCrt.pem")));
    }

    @Test
    public void testLoadPemCertOnClassPath() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("publicCrt.pem", "issuer");
        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo);
        assertNotNull(keyLocationResolver.verificationKey);
        assertEquals(keyLocationResolver.verificationKey, keyLocationResolver.resolveKey(signature, emptyList()));
        assertEquals(keyLocationResolver.verificationKey,
                KeyLocationResolver.tryAsPEMCertificate(keyLocationResolver.readKeyContent("publicCrt.pem")));
    }

    @Test
    public void testLoadPemOnClassPath() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("publicKey.pem", "issuer");
        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo);
        assertNotNull(keyLocationResolver.verificationKey);
        assertEquals(keyLocationResolver.verificationKey, keyLocationResolver.resolveKey(signature, emptyList()));
        assertEquals(keyLocationResolver.verificationKey,
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
        assertNotNull(keyLocationResolver.verificationKey);
        assertEquals(keyLocationResolver.verificationKey, keyLocationResolver.resolveKey(signature, emptyList()));
        assertEquals(keyLocationResolver.verificationKey, keyLocationResolver.getJsonWebKey("key1"));
    }

}
