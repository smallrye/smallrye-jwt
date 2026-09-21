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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

import io.smallrye.jwe.JsonWebEncryption;
import io.smallrye.jwe.JweException;
import io.smallrye.jwk.AsymmetricJsonWebKey;
import io.smallrye.jwk.JsonWebKey;
import io.smallrye.jwt.auth.UnresolvableKeyException;
import io.smallrye.jwt.util.ResourceUtils;
import io.smallrye.jwt.util.ResourceUtils.UrlStreamResolver;

@ExtendWith(MockitoExtension.class)
class DecryptionKeyLocationResolverTest {

    @Mock
    UrlStreamResolver urlResolver;

    @Test
    void loadPemKeyWithWrongLocation() {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();
        contextInfo.setDecryptionKeyLocation("wrong_location.pem");
        assertThrows(UnresolvableKeyException.class,
                () -> new DecryptionKeyLocationResolver(contextInfo).resolveKey(jweObject(null)));
    }

    @Test
    void loadRsaKeyFromHttpsJwks() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();
        contextInfo.setDecryptionKeyLocation("https://github.com/my_key.jwks");
        contextInfo.setJwksRefreshInterval(10);

        RSAKey rsaJwk = new RSAKeyGenerator(2048).keyID("1").generate();
        JsonWebKey jsonWebKey = JsonWebKey.parse(rsaJwk.toJSONString());

        DecryptionKeyLocationResolver keyLocationResolver = new DecryptionKeyLocationResolver(contextInfo) {
            @Override
            protected RemoteJwkSet createRemoteJwkSet(String location) {
                return new RemoteJwkSet(location, authContextInfo) {
                    @Override
                    void refresh() {
                        // no-op, keys set directly
                    }

                    @Override
                    List<JsonWebKey> getKeys() {
                        return Collections.singletonList(jsonWebKey);
                    }
                };
            }
        };

        assertEquals(rsaJwk.toPrivateKey(), keyLocationResolver.resolveKey(jweObject("1")));
        assertNull(keyLocationResolver.key);
    }

    @Test
    void loadSecretKeyFromHttpsJwks() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();
        contextInfo.setDecryptionKeyLocation("https://github.com/my_key.jwks");
        contextInfo.setJwksRefreshInterval(10);

        SecretKey secretKey = new SecretKeySpec("123456789ABCDEF".getBytes(StandardCharsets.UTF_8), "AES");
        OctetSequenceKey jwk = new OctetSequenceKey.Builder(secretKey).keyID("1").build();
        JsonWebKey jsonWebKey = JsonWebKey.parse(jwk.toJSONString());

        DecryptionKeyLocationResolver keyLocationResolver = new DecryptionKeyLocationResolver(contextInfo) {
            @Override
            protected RemoteJwkSet createRemoteJwkSet(String location) {
                return new RemoteJwkSet(location, authContextInfo) {
                    @Override
                    void refresh() {
                        // no-op, keys set directly
                    }

                    @Override
                    List<JsonWebKey> getKeys() {
                        return Collections.singletonList(jsonWebKey);
                    }
                };
            }
        };

        assertEquals(secretKey, keyLocationResolver.resolveKey(jweObject("1")));
        assertNull(keyLocationResolver.key);
    }

    @Test
    void loadHttpsJwksNonMathchingKidAndRefresh() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();
        contextInfo.setDecryptionKeyLocation("https://github.com/my_key.jwks");
        contextInfo.setJwksRefreshInterval(10);

        RSAKey originalJwk = new RSAKeyGenerator(2048).generate();
        JsonWebKey jwkWithKid1 = JsonWebKey.parse(new RSAKey.Builder(originalJwk).keyID("1").build().toJSONString());
        JsonWebKey jwkWithKid2 = JsonWebKey.parse(new RSAKey.Builder(originalJwk).keyID("2").build().toJSONString());
        AtomicInteger fetchCount = new AtomicInteger(0);

        DecryptionKeyLocationResolver keyLocationResolver = new DecryptionKeyLocationResolver(contextInfo) {
            @Override
            protected RemoteJwkSet createRemoteJwkSet(String location) {
                return new RemoteJwkSet(location, authContextInfo) {
                    private List<JsonWebKey> keys = Collections.emptyList();

                    @Override
                    void refresh() {
                        int count = fetchCount.incrementAndGet();
                        // Construction call: return JWK with non-matching kid "2"
                        // Forced refresh call: return JWK with matching kid "1"
                        keys = Collections.singletonList(count == 1 ? jwkWithKid2 : jwkWithKid1);
                    }

                    @Override
                    List<JsonWebKey> getKeys() {
                        return keys;
                    }
                };
            }
        };

        assertEquals(originalJwk.toPrivateKey(), keyLocationResolver.resolveKey(jweObject("1")));
        assertNull(keyLocationResolver.key);
    }

    @Test
    void loadHttpsJwksNonMathchingKidAndRefreshDeclined() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();
        contextInfo.setDecryptionKeyLocation("https://github.com/my_key.jwks");
        contextInfo.setJwksRefreshInterval(10);
        contextInfo.setForcedJwksRefreshInterval(10);

        RSAKey originalJwk = new RSAKeyGenerator(2048).generate();
        JsonWebKey jwkWithKid1 = JsonWebKey.parse(new RSAKey.Builder(originalJwk).keyID("1").build().toJSONString());
        JsonWebKey jwkWithKid2 = JsonWebKey.parse(new RSAKey.Builder(originalJwk).keyID("2").build().toJSONString());
        AtomicInteger fetchCount = new AtomicInteger(0);

        DecryptionKeyLocationResolver keyLocationResolver = Mockito.spy(new DecryptionKeyLocationResolver(contextInfo) {
            @Override
            protected RemoteJwkSet createRemoteJwkSet(String location) {
                return new RemoteJwkSet(location, authContextInfo) {
                    private List<JsonWebKey> keys = Collections.emptyList();

                    @Override
                    void refresh() {
                        int count = fetchCount.incrementAndGet();
                        // Construction call: return JWK with non-matching kid "2"
                        // Forced refresh call: return JWK with matching kid "1"
                        keys = Collections.singletonList(count == 1 ? jwkWithKid2 : jwkWithKid1);
                    }

                    @Override
                    List<JsonWebKey> getKeys() {
                        return keys;
                    }
                };
            }
        });

        // First call: kid "1" not found in cache (has "2"), forced refresh succeeds and returns kid "1"
        assertEquals(originalJwk.toPrivateKey(), keyLocationResolver.resolveKey(jweObject("1")));
        assertNull(keyLocationResolver.key);

        // Second call with non-matching kid: forced refresh is declined (interval not elapsed)
        assertThrows(UnresolvableKeyException.class, () -> keyLocationResolver.resolveKey(jweObject("99")));
    }

    @Test
    void loadHttpsPem() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();
        contextInfo.setDecryptionKeyLocation("https://github.com/my_key.pem");
        contextInfo.setJwksRefreshInterval(10);

        Mockito.doReturn(ResourceUtils.getAsClasspathResource("privateKey.pem"))
                .when(urlResolver).resolve(Mockito.any());
        DecryptionKeyLocationResolver keyLocationResolver = new DecryptionKeyLocationResolver(contextInfo) {
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
        assertEquals(keyLocationResolver.key, keyLocationResolver.resolveKey(jweObject(null)));
        assertEquals(keyLocationResolver.key,
                DecryptionKeyLocationResolver.tryAsPEMPrivateKey(keyLocationResolver.readKeyContent("privateKey.pem")));
    }

    @Test
    void loadPemOnClassPath() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();
        contextInfo.setDecryptionKeyLocation("privateKey.pem");
        DecryptionKeyLocationResolver keyLocationResolver = new DecryptionKeyLocationResolver(contextInfo);
        assertNotNull(keyLocationResolver.key);
        assertEquals(keyLocationResolver.key, keyLocationResolver.resolveKey(jweObject(null)));
        assertEquals(keyLocationResolver.key,
                DecryptionKeyLocationResolver.tryAsPEMPrivateKey(keyLocationResolver.readKeyContent("privateKey.pem")));
    }

    @Test
    void loadJWKOnClassPath() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();
        contextInfo.setDecryptionKeyLocation("decryptPrivateKey.jwk");
        contextInfo.setTokenDecryptionKeyId("key1");
        DecryptionKeyLocationResolver keyLocationResolver = new DecryptionKeyLocationResolver(contextInfo);
        assertNotNull(keyLocationResolver.key);
        assertEquals(keyLocationResolver.key, keyLocationResolver.resolveKey(jweObject("key1")));
        assertEquals(keyLocationResolver.key,
                ((AsymmetricJsonWebKey) keyLocationResolver.getJsonWebKey("key1", null)).privateKey());
    }

    private static JsonWebEncryption jweObject(String kid) throws JweException {
        JWEHeader.Builder builder = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);
        if (kid != null) {
            builder.keyID(kid);
        }
        // the resolver only looks at the headers, so the remaining parts of the sequence can be empty
        return JsonWebEncryption.parse(builder.build().toBase64URL() + "....");
    }
}
