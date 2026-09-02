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

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.security.Key;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.Set;

import org.jose4j.http.SimpleGet;
import org.jose4j.http.SimpleResponse;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.Headers;
import org.jose4j.lang.UnresolvableKeyException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import io.smallrye.jwt.algorithm.SignatureAlgorithm;

@ExtendWith(MockitoExtension.class)
class AwsAlbKeyResolverTest {

    private static final String AWS_ALB_KEY = "-----BEGIN PUBLIC KEY-----"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjPHY1j9umvc8nZEswOzs+lPpLKLn"
            + "qCBqvyZGJfBlXapmtGiqYEwpIqh/lZdkr4wDii7CP1DzIUSHONbc+jufiQ=="
            + "-----END PUBLIC KEY-----";

    @Mock
    JsonWebSignature signature;
    @Mock
    Headers headers;
    @Mock
    SimpleGet simpleGet;
    @Mock
    SimpleResponse simpleResponse;

    AwsAlbKeyResolverTest() throws Exception {

    }

    @ParameterizedTest
    @ValueSource(strings = {
            "c2f80c8b-c05c-4068-af14-17299f7896b1",
            "simple-alpha",
            "12345",
            "a-b-c-d" })
    void loadAwsAlbVerificationKey(String kid) throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(
                "https://localhost:8080",
                "https://cognito-idp.eu-central-1.amazonaws.com");
        contextInfo.setSignatureAlgorithm(Set.of(SignatureAlgorithm.ES256));

        AwsAlbKeyResolver keyLocationResolver = new AwsAlbKeyResolver(contextInfo);
        keyLocationResolver = Mockito.spy(keyLocationResolver);

        when(keyLocationResolver.getHttpGet()).thenReturn(simpleGet);

        when(simpleGet.get("https://localhost:8080/" + kid))
                .thenReturn(simpleResponse);

        when(simpleResponse.getBody()).thenReturn(AWS_ALB_KEY);

        when(signature.getHeaders()).thenReturn(headers);
        when(headers.getStringHeaderValue(JsonWebKey.KEY_ID_PARAMETER)).thenReturn(kid);

        Key key = keyLocationResolver.resolveKey(signature, List.of());
        assertTrue(key instanceof ECPublicKey);
        // Confirm the cached key is returned
        Key key2 = keyLocationResolver.resolveKey(signature, List.of());
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
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(
                "https://localhost:8080",
                "https://cognito-idp.eu-central-1.amazonaws.com");
        contextInfo.setSignatureAlgorithm(Set.of(SignatureAlgorithm.ES256));

        AwsAlbKeyResolver keyLocationResolver = new AwsAlbKeyResolver(contextInfo);

        when(signature.getHeaders()).thenReturn(headers);
        when(headers.getStringHeaderValue(JsonWebKey.KEY_ID_PARAMETER)).thenReturn(kid);

        assertThrows(UnresolvableKeyException.class, () -> keyLocationResolver.resolveKey(signature, List.of()));
    }

    @Test
    void rejectNullKid() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(
                "https://localhost:8080",
                "https://cognito-idp.eu-central-1.amazonaws.com");
        contextInfo.setSignatureAlgorithm(Set.of(SignatureAlgorithm.ES256));

        AwsAlbKeyResolver keyLocationResolver = new AwsAlbKeyResolver(contextInfo);

        when(signature.getHeaders()).thenReturn(headers);
        when(headers.getStringHeaderValue(JsonWebKey.KEY_ID_PARAMETER)).thenReturn(null);

        assertThrows(UnresolvableKeyException.class, () -> keyLocationResolver.resolveKey(signature, List.of()));
    }

}
