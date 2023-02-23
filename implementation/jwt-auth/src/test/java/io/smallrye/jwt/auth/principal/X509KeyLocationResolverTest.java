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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;

import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.keys.X509Util;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.UnresolvableKeyException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import io.smallrye.jwt.util.KeyUtils;
import io.smallrye.jwt.util.ResourceUtils;
import io.smallrye.jwt.util.ResourceUtils.UrlStreamResolver;

@ExtendWith(MockitoExtension.class)
class X509KeyLocationResolverTest {

    @Mock
    JsonWebSignature signature;
    @Mock
    HttpsJwks mockedHttpsJwks;
    @Mock
    UrlStreamResolver urlResolver;

    RSAPublicKey key;
    String x5t;
    String x5tS256;
    String x5c;

    X509KeyLocationResolverTest() throws Exception {
        X509Certificate certificate = KeyUtils.getCertificate(ResourceUtils.readResource("publicCrt.pem"));
        x5t = X509Util.x5t(certificate);
        x5tS256 = X509Util.x5tS256(certificate);
        x5c = new X509Util().toBase64(certificate);
        key = (RSAPublicKey) certificate.getPublicKey();
    }

    @Test
    void loadHttpsJwksWithX5t() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("https://github.com/my_key.jwks", "issuer");
        contextInfo.setJwksRefreshInterval(10);

        RsaJsonWebKey jwk = new RsaJsonWebKey(key);
        jwk.setOtherParameter("x5c", Collections.singletonList(x5c));
        when(mockedHttpsJwks.getJsonWebKeys()).thenReturn(Collections.singletonList(jwk));
        X509KeyLocationResolver keyLocationResolver = new X509KeyLocationResolver(contextInfo) {
            protected HttpsJwks initializeHttpsJwks(String loc) {
                return mockedHttpsJwks;
            }
        };
        keyLocationResolver = Mockito.spy(keyLocationResolver);
        when(signature.getX509CertSha1ThumbprintHeaderValue()).thenReturn(x5t);
        assertEquals(key, keyLocationResolver.resolveKey(signature, emptyList()));
    }

    @Test
    void loadHttpsPemCert() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("https://github.com/my_key.crt", "issuer");
        contextInfo.setJwksRefreshInterval(10);
        Mockito.doThrow(new JoseException("")).when(mockedHttpsJwks).refresh();
        Mockito.doReturn(ResourceUtils.getAsClasspathResource("publicCrt.pem"))
                .when(urlResolver).resolve(Mockito.any());
        X509KeyLocationResolver keyLocationResolver = new X509KeyLocationResolver(contextInfo) {
            protected HttpsJwks initializeHttpsJwks(String loc) {
                return mockedHttpsJwks;
            }

            protected UrlStreamResolver getUrlResolver() {
                return urlResolver;
            }
        };
        when(signature.getX509CertSha1ThumbprintHeaderValue()).thenReturn(x5t);
        assertEquals(key, keyLocationResolver.resolveKey(signature, emptyList()));
    }

    @Test
    void loadPemCertOnClassPath() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("publicCrt.pem", "issuer");
        X509KeyLocationResolver keyLocationResolver = new X509KeyLocationResolver(contextInfo);
        when(signature.getX509CertSha1ThumbprintHeaderValue()).thenReturn(x5t);
        assertEquals(key, keyLocationResolver.resolveKey(signature, emptyList()));
    }

    @Test
    void loadJWKWithCertOnClassPathWithX5t() throws Exception {
        RsaJsonWebKey jwk = new RsaJsonWebKey(key);
        jwk.setOtherParameter("x5c", Collections.singletonList(x5c));
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();
        contextInfo.setPublicKeyContent(jwk.toJson());
        X509KeyLocationResolver keyLocationResolver = new X509KeyLocationResolver(contextInfo);
        when(signature.getX509CertSha1ThumbprintHeaderValue()).thenReturn(x5t);
        assertEquals(key, keyLocationResolver.resolveKey(signature, emptyList()));
    }

    @Test
    void loadJWKWithCertOnClassPathWithX5tS256() throws Exception {
        RsaJsonWebKey jwk = new RsaJsonWebKey(key);
        jwk.setOtherParameter("x5c", Collections.singletonList(x5c));
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();
        contextInfo.setPublicKeyContent(jwk.toJson());
        X509KeyLocationResolver keyLocationResolver = new X509KeyLocationResolver(contextInfo);
        when(signature.getX509CertSha256ThumbprintHeaderValue()).thenReturn(x5tS256);
        assertEquals(key, keyLocationResolver.resolveKey(signature, emptyList()));
    }

    @Test
    void loadJWKWithCertOnClassPathWithWrongX5tS256() throws Exception {
        RsaJsonWebKey jwk = new RsaJsonWebKey(key);
        jwk.setOtherParameter("x5c", Collections.singletonList(x5c));
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();
        contextInfo.setPublicKeyContent(jwk.toJson());
        X509KeyLocationResolver keyLocationResolver = new X509KeyLocationResolver(contextInfo);
        when(signature.getX509CertSha256ThumbprintHeaderValue()).thenReturn(x5tS256 + "1");
        assertThrows(UnresolvableKeyException.class, () -> keyLocationResolver.resolveKey(signature, emptyList()));
    }
}
