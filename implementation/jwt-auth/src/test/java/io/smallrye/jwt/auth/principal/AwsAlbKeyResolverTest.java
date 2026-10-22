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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Key;
import java.security.interfaces.ECPublicKey;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;

import io.smallrye.jws.JsonWebSignature;
import io.smallrye.jws.JwsException;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.auth.UnresolvableKeyException;
import io.smallrye.jwt.util.KeyUtils;

class AwsAlbKeyResolverTest {

    private static final String AWS_ALB_KEY = "-----BEGIN PUBLIC KEY-----"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjPHY1j9umvc8nZEswOzs+lPpLKLn"
            + "qCBqvyZGJfBlXapmtGiqYEwpIqh/lZdkr4wDii7CP1DzIUSHONbc+jufiQ=="
            + "-----END PUBLIC KEY-----";

    @ParameterizedTest
    @ValueSource(strings = {
            "c2f80c8b-c05c-4068-af14-17299f7896b1",
            "simple-alpha",
            "12345",
            "a-b-c-d" })
    void loadAwsAlbVerificationKey(String kid) throws Exception {
        JWTAuthContextInfo contextInfo = createContextInfo();

        AtomicReference<String> requestedKid = new AtomicReference<>();
        AwsAlbKeyResolver keyLocationResolver = new AwsAlbKeyResolver(contextInfo) {
            @Override
            protected Key retrieveKey(String keyId) throws UnresolvableKeyException {
                requestedKid.set(keyId);
                try {
                    return KeyUtils.decodePublicKey(AWS_ALB_KEY, SignatureAlgorithm.ES256);
                } catch (Exception e) {
                    throw new UnresolvableKeyException("Failed to decode key", e);
                }
            }
        };

        Key key = keyLocationResolver.resolveKey(signedJwt(kid));
        assertTrue(key instanceof ECPublicKey);
        assertEquals(kid, requestedKid.get());
        // Confirm the cached key is returned
        Key key2 = keyLocationResolver.resolveKey(signedJwt(kid));
        assertTrue(key2 == key);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "../../../etc/passwd",
            "..",
            "sub/path",
            "key%2fpath",
            "..%2f..%2fevil",
            "..%252f..%252fevil",
            "https://evil.com/key",
            "key@evil.com",
            "key?a=b",
            "key#frag",
            "key with space",
            "key\nInjected",
            "key:1234",
            "with_underscore",
            "" })
    void rejectUnsafeKid(String kid) throws Exception {
        AwsAlbKeyResolver keyLocationResolver = new AwsAlbKeyResolver(createContextInfo());

        assertThrows(UnresolvableKeyException.class, () -> keyLocationResolver.resolveKey(signedJwt(kid)));
    }

    @Test
    void rejectNullKid() throws Exception {
        AwsAlbKeyResolver keyLocationResolver = new AwsAlbKeyResolver(createContextInfo());

        assertThrows(UnresolvableKeyException.class, () -> keyLocationResolver.resolveKey(signedJwt(null)));
    }

    private static JWTAuthContextInfo createContextInfo() {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(
                "https://localhost:8080",
                "https://cognito-idp.eu-central-1.amazonaws.com");
        contextInfo.setSignatureAlgorithm(Set.of(SignatureAlgorithm.ES256));
        return contextInfo;
    }

    private static JsonWebSignature signedJwt(String kid) throws JwsException {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(kid).build();
        // the resolver only selects a key from the headers and never verifies the token,
        // so the claims and signature segments are placeholders
        return JsonWebSignature.parse(header.toBase64URL() + "." + Base64URL.encode("{}") + ".signature");
    }
}
