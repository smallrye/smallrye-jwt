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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.auth.JsonWebSignature;
import io.smallrye.jwt.auth.UnresolvableKeyException;
import io.smallrye.jwt.util.KeyUtils;
import io.smallrye.jwt.util.ResourceUtils;
import io.smallrye.jwt.util.ResourceUtils.UrlStreamResolver;

@ExtendWith(MockitoExtension.class)
class KeyLocationResolverTest {

    @Mock
    UrlStreamResolver urlResolver;

    RSAPublicKey rsaKey;
    SecretKey secretKey;

    private static JsonWebSignature signedJwt(String kid, String alg) {
        JWSHeader.Builder builder = new JWSHeader.Builder(JWSAlgorithm.parse(alg));
        if (kid != null) {
            builder.keyID(kid);
        }
        return new JsonWebSignatureImpl(new SignedJWT(builder.build(), new JWTClaimsSet.Builder().build()), null);
    }

    KeyLocationResolverTest() throws Exception {
        rsaKey = (RSAPublicKey) KeyUtils.generateKeyPair(2048).getPublic();
        secretKey = new SecretKeySpec("123456789ABCDEF".getBytes(StandardCharsets.UTF_8), "AES");
    }

    @Test
    void loadPemKeyWithWrongLocation() {
        assertThrows(UnresolvableKeyException.class,
                () -> new KeyLocationResolver(new JWTAuthContextInfo("wrong_location.pem", null)));
    }

    @Test
    void loadRsaKeyFromHttpsJwks() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("https://github.com/my_key.jwks", "issuer");
        contextInfo.setJwksRefreshInterval(10);

        RSAKey rsaJwk = new RSAKey.Builder(rsaKey).keyID("1").build();

        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo) {
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

        assertEquals(rsaKey, keyLocationResolver.resolveKey(signedJwt("1", "RS256")));
        assertNull(keyLocationResolver.key);
    }

    @Test
    void loadRsaKeyFromHttpsJwksWithCertAndTrustAll() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("https://github.com/my_key.jwks", "issuer");
        contextInfo.setTlsCertificate(KeyUtils.readKeyContent("publicCrt.pem"));
        contextInfo.setTlsTrustAll(true);
        contextInfo.setJwksRefreshInterval(10);

        RSAKey rsaJwk = new RSAKey.Builder(rsaKey).keyID("1").build();

        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo) {
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

        assertEquals(rsaKey, keyLocationResolver.resolveKey(signedJwt("1", "RS256")));
        assertNull(keyLocationResolver.key);
    }

    @Test
    void loadRsaKeyFromHttpsJwksWithCertPathAndTrustedHostsAndProxy() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("https://github.com/my_key.jwks", "issuer");
        contextInfo.setTlsCertificatePath("publicCrt.pem");
        contextInfo.setTlsTrustedHosts(new HashSet<>(Arrays.asList("trusted-host")));
        contextInfo.setHttpProxyHost("proxyhost");
        contextInfo.setJwksRefreshInterval(10);

        RSAKey rsaJwk = new RSAKey.Builder(rsaKey).keyID("1").build();

        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo) {
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

        assertEquals(rsaKey, keyLocationResolver.resolveKey(signedJwt("1", "RS256")));
        assertNull(keyLocationResolver.key);
    }

    @Test
    void keepsRsaKeyFromHttpsJwksWhenErrorDuringRefresh() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("https://github.com/my_key.jwks", "issuer");
        contextInfo.setJwksRefreshInterval(10);
        contextInfo.setJwksRetainCacheOnErrorDuration(10);

        RSAKey rsaJwk = new RSAKey.Builder(rsaKey).keyID("1").build();
        AtomicBoolean shouldFail = new AtomicBoolean(false);

        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo) {
            @Override
            protected RemoteJwkSet createRemoteJwkSet(String location) {
                return new RemoteJwkSet(location, authContextInfo) {
                    private List<JWK> keys = Collections.singletonList(rsaJwk);

                    @Override
                    void refresh() throws IOException {
                        if (shouldFail.get()) {
                            throw new IOException("Connection failed");
                        }
                    }

                    @Override
                    List<JWK> getKeys() {
                        if (shouldFail.get()) {
                            try {
                                refresh();
                            } catch (IOException e) {
                                // Retain cached keys on error
                            }
                        }
                        return keys;
                    }
                };
            }
        };

        assertEquals(rsaKey, keyLocationResolver.resolveKey(signedJwt("1", "RS256")));

        // Make subsequent fetches fail
        shouldFail.set(true);

        // Should retain cached key despite fetch failure
        assertEquals(rsaKey, keyLocationResolver.resolveKey(signedJwt("1", "RS256")));
    }

    @Test
    void loadRsaKeyFromHttpJwks() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("http://github.com/my_key.jwks", "issuer");
        contextInfo.setJwksRefreshInterval(10);

        RSAKey rsaJwk = new RSAKey.Builder(rsaKey).keyID("1").build();

        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo) {
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

        assertEquals(rsaKey, keyLocationResolver.resolveKey(signedJwt("1", "RS256")));
        assertNull(keyLocationResolver.key);
    }

    @Test
    void loadSecretKeyFromHttpsJwks() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("https://github.com/my_key.jwks", "issuer");
        contextInfo.setJwksRefreshInterval(10);

        OctetSequenceKey jwk = new OctetSequenceKey.Builder(secretKey).keyID("1").build();

        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo) {
            @Override
            protected RemoteJwkSet createRemoteJwkSet(String location) {
                return new RemoteJwkSet(location, authContextInfo) {
                    @Override
                    void refresh() {
                        // no-op, keys set directly
                    }

                    @Override
                    List<JWK> getKeys() {
                        return Collections.singletonList(jwk);
                    }
                };
            }
        };

        // Compare key bytes - Nimbus toSecretKey() uses "NONE" algorithm while our test key uses "AES"
        assertArrayEquals(secretKey.getEncoded(),
                ((SecretKey) keyLocationResolver.resolveKey(signedJwt("1", "RS256"))).getEncoded());
        assertNull(keyLocationResolver.key);
    }

    @Test
    void loadHttpsJwksNonMathchingKidAndRefresh() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("https://github.com/my_key.jwks", "issuer");
        contextInfo.setJwksRefreshInterval(10);

        AtomicInteger fetchCount = new AtomicInteger(0);

        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo) {
            @Override
            protected RemoteJwkSet createRemoteJwkSet(String location) {
                return new RemoteJwkSet(location, authContextInfo) {
                    private List<JWK> keys = Collections.emptyList();

                    @Override
                    void refresh() {
                        int count = fetchCount.incrementAndGet();
                        // Construction: return JWK with non-matching kid "2"
                        // Forced refresh: return JWK with matching kid "1"
                        RSAKey jwk = count == 1
                                ? new RSAKey.Builder(rsaKey).keyID("2").build()
                                : new RSAKey.Builder(rsaKey).keyID("1").build();
                        keys = Collections.singletonList(jwk);
                    }

                    @Override
                    List<JWK> getKeys() {
                        return keys;
                    }
                };
            }
        };

        assertEquals(rsaKey, keyLocationResolver.resolveKey(signedJwt("1", "RS256")));
        assertNull(keyLocationResolver.key);
    }

    @Test
    void loadHttpJwksNonMathchingKidAndRefresh() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("http://github.com/my_key.jwks", "issuer");
        contextInfo.setJwksRefreshInterval(10);

        AtomicInteger fetchCount = new AtomicInteger(0);

        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo) {
            @Override
            protected RemoteJwkSet createRemoteJwkSet(String location) {
                return new RemoteJwkSet(location, authContextInfo) {
                    private List<JWK> keys = Collections.emptyList();

                    @Override
                    void refresh() {
                        int count = fetchCount.incrementAndGet();
                        RSAKey jwk = count == 1
                                ? new RSAKey.Builder(rsaKey).keyID("2").build()
                                : new RSAKey.Builder(rsaKey).keyID("1").build();
                        keys = Collections.singletonList(jwk);
                    }

                    @Override
                    List<JWK> getKeys() {
                        return keys;
                    }
                };
            }
        };

        assertEquals(rsaKey, keyLocationResolver.resolveKey(signedJwt("1", "RS256")));
        assertNull(keyLocationResolver.key);
    }

    @Test
    void loadHttpsJwksNonMathchingKidAndRefreshDeclined() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("https://github.com/my_key.jwks", "issuer");
        contextInfo.setJwksRefreshInterval(10);
        contextInfo.setForcedJwksRefreshInterval(10);

        AtomicInteger fetchCount = new AtomicInteger(0);

        KeyLocationResolver keyLocationResolver = Mockito.spy(new KeyLocationResolver(contextInfo) {
            @Override
            protected RemoteJwkSet createRemoteJwkSet(String location) {
                return new RemoteJwkSet(location, authContextInfo) {
                    private List<JWK> keys = Collections.emptyList();

                    @Override
                    void refresh() {
                        int count = fetchCount.incrementAndGet();
                        RSAKey jwk = count == 1
                                ? new RSAKey.Builder(rsaKey).keyID("2").build()
                                : new RSAKey.Builder(rsaKey).keyID("1").build();
                        keys = Collections.singletonList(jwk);
                    }

                    @Override
                    List<JWK> getKeys() {
                        return keys;
                    }
                };
            }
        });

        // First call: kid "1" not in cache (has "2"), forced refresh succeeds and returns kid "1"
        assertEquals(rsaKey, keyLocationResolver.resolveKey(signedJwt("1", "RS256")));
        assertNull(keyLocationResolver.key);

        // Second call with non-matching kid: forced refresh is declined (interval not elapsed)
        assertThrows(UnresolvableKeyException.class, () -> keyLocationResolver.resolveKey(signedJwt("99", "RS256")));
    }

    @Test
    void loadHttpsPemCrt() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("https://github.com/my_key.crt", "issuer");
        contextInfo.setJwksRefreshInterval(10);

        Mockito.doReturn(ResourceUtils.getAsClasspathResource("publicCrt.pem"))
                .when(urlResolver).resolve(Mockito.any());
        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo) {
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
        assertNotNull(keyLocationResolver.key);
        assertEquals(keyLocationResolver.key, keyLocationResolver.resolveKey(signedJwt(null, "RS256")));
        assertEquals(keyLocationResolver.key,
                keyLocationResolver.tryAsPEMCertificate(keyLocationResolver.readKeyContent("publicCrt.pem")));
    }

    @Test
    void loadPemCertOnClassPath() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("publicCrt.pem", "issuer");
        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo);
        assertNotNull(keyLocationResolver.key);
        assertEquals(keyLocationResolver.key, keyLocationResolver.resolveKey(signedJwt(null, "RS256")));
        assertEquals(keyLocationResolver.key,
                keyLocationResolver.tryAsPEMCertificate(keyLocationResolver.readKeyContent("publicCrt.pem")));
    }

    @Test
    void loadPemOnClassPath() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("publicKey.pem", "issuer");
        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo);
        assertNotNull(keyLocationResolver.key);
        assertEquals(keyLocationResolver.key, keyLocationResolver.resolveKey(signedJwt(null, "RS256")));
        assertEquals(keyLocationResolver.key,
                KeyLocationResolver.tryAsPEMPublicKey(keyLocationResolver.readKeyContent("publicKey.pem"),
                        SignatureAlgorithm.RS256));
    }

    @Test
    void loadJWKOnClassPath() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("publicKey.jwk", "issuer");
        contextInfo.setTokenKeyId("key1");
        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo);
        assertNotNull(keyLocationResolver.key);
        assertEquals(keyLocationResolver.key, keyLocationResolver.resolveKey(signedJwt("key1", "RS256")));
        assertEquals(keyLocationResolver.key,
                ((com.nimbusds.jose.jwk.AsymmetricJWK) keyLocationResolver.getJsonWebKey("key1", null)).toPublicKey());
    }
}
