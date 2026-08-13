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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.smallrye.jwt.auth.JsonWebSignature;
import io.smallrye.jwt.auth.UnresolvableKeyException;
import io.smallrye.jwt.util.KeyUtils;
import io.smallrye.jwt.util.ResourceUtils;
import io.smallrye.jwt.util.ResourceUtils.UrlStreamResolver;

@ExtendWith(MockitoExtension.class)
class X509KeyLocationResolverTest {

    @Mock
    UrlStreamResolver urlResolver;

    private static JsonWebSignature signedJwt(JWSHeader header) {
        return new JsonWebSignatureImpl(new SignedJWT(header, new JWTClaimsSet.Builder().build()), null);
    }

    RSAPublicKey key;
    String x5t;
    String x5tS256;
    com.nimbusds.jose.util.Base64 certBase64;
    X509Certificate certificate;

    X509KeyLocationResolverTest() throws Exception {
        certificate = KeyUtils.getCertificate(ResourceUtils.readResource("publicCrt.pem"));
        x5t = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-1").digest(certificate.getEncoded()));
        x5tS256 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
        certBase64 = com.nimbusds.jose.util.Base64.encode(certificate.getEncoded());
        key = (RSAPublicKey) certificate.getPublicKey();
    }

    @Test
    void loadHttpsJwksWithX5t() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("https://github.com/my_key.jwks", "issuer");
        contextInfo.setJwksRefreshInterval(10);

        RSAKey rsaJwk = new RSAKey.Builder(key)
                .x509CertChain(Collections.singletonList(certBase64))
                .build();

        X509KeyLocationResolver keyLocationResolver = new X509KeyLocationResolver(contextInfo) {
            @Override
            protected RemoteJwkSet createRemoteJwkSet(String location) {
                return new RemoteJwkSet(location, authContextInfo) {
                    @Override
                    void refresh() {
                        // no-op, keys set directly
                    }

                    @Override
                    List<JWK> getKeys() {
                        return Collections.singletonList(rsaJwk);
                    }
                };
            }
        };

        assertEquals(key, keyLocationResolver
                .resolveKey(
                        signedJwt(new JWSHeader.Builder(JWSAlgorithm.RS256).x509CertThumbprint(new Base64URL(x5t)).build())));
    }

    @Test
    void loadHttpsPemCert() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("https://github.com/my_key.crt", "issuer");
        contextInfo.setJwksRefreshInterval(10);
        Mockito.doReturn(ResourceUtils.getAsClasspathResource("publicCrt.pem"))
                .when(urlResolver).resolve(Mockito.any());
        X509KeyLocationResolver keyLocationResolver = new X509KeyLocationResolver(contextInfo) {
            @Override
            protected RemoteJwkSet createRemoteJwkSet(String location) {
                return new RemoteJwkSet(location, authContextInfo) {
                    @Override
                    void refresh() throws IOException {
                        throw new IOException("Not a JWKS endpoint");
                    }
                };
            }

            @Override
            protected UrlStreamResolver getUrlResolver() {
                return urlResolver;
            }
        };
        assertEquals(key, keyLocationResolver
                .resolveKey(
                        signedJwt(new JWSHeader.Builder(JWSAlgorithm.RS256).x509CertThumbprint(new Base64URL(x5t)).build())));
    }

    @Test
    void loadPemCertOnClassPath() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("publicCrt.pem", "issuer");
        X509KeyLocationResolver keyLocationResolver = new X509KeyLocationResolver(contextInfo);
        assertEquals(key, keyLocationResolver
                .resolveKey(
                        signedJwt(new JWSHeader.Builder(JWSAlgorithm.RS256).x509CertThumbprint(new Base64URL(x5t)).build())));
    }

    @Test
    void loadJWKWithCertOnClassPathWithX5t() throws Exception {
        RSAKey rsaJwk = new RSAKey.Builder(key)
                .x509CertChain(Collections.singletonList(certBase64))
                .build();
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();
        contextInfo.setPublicKeyContent(rsaJwk.toJSONString());
        X509KeyLocationResolver keyLocationResolver = new X509KeyLocationResolver(contextInfo);
        assertEquals(key, keyLocationResolver
                .resolveKey(
                        signedJwt(new JWSHeader.Builder(JWSAlgorithm.RS256).x509CertThumbprint(new Base64URL(x5t)).build())));
    }

    @Test
    void loadJWKWithCertOnClassPathWithX5tS256() throws Exception {
        RSAKey rsaJwk = new RSAKey.Builder(key)
                .x509CertChain(Collections.singletonList(certBase64))
                .build();
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();
        contextInfo.setPublicKeyContent(rsaJwk.toJSONString());
        X509KeyLocationResolver keyLocationResolver = new X509KeyLocationResolver(contextInfo);
        assertEquals(key, keyLocationResolver.resolveKey(signedJwt(
                new JWSHeader.Builder(JWSAlgorithm.RS256).x509CertSHA256Thumbprint(new Base64URL(x5tS256)).build())));
    }

    @Test
    void loadJWKWithCertOnClassPathWithWrongX5tS256() throws Exception {
        // Use a JWK Set with two entries so the single-certificate fallback does not apply
        RSAKey rsaJwk1 = new RSAKey.Builder(key)
                .x509CertChain(Collections.singletonList(certBase64))
                .keyID("cert1")
                .build();
        RSAKey rsaJwk2 = new RSAKey.Builder(key)
                .x509CertChain(Collections.singletonList(certBase64))
                .keyID("cert2")
                .build();
        JWKSet jwkSet = new JWKSet(Arrays.asList(rsaJwk1, rsaJwk2));
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();
        contextInfo.setPublicKeyContent(jwkSet.toString());
        X509KeyLocationResolver keyLocationResolver = new X509KeyLocationResolver(contextInfo);
        assertThrows(UnresolvableKeyException.class,
                () -> keyLocationResolver.resolveKey(signedJwt(new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .x509CertSHA256Thumbprint(new Base64URL(x5tS256 + "1")).build())));
    }
}
