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

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.security.Key;
import java.security.interfaces.ECPublicKey;
import java.util.List;

import org.jose4j.http.SimpleGet;
import org.jose4j.http.SimpleResponse;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.Headers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
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

    @Test
    void loadAwsAlbVerificationKey() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(
                "https://localhost:8080",
                "https://cognito-idp.eu-central-1.amazonaws.com");
        contextInfo.setSignatureAlgorithm(SignatureAlgorithm.ES256);

        AwsAlbKeyResolver keyLocationResolver = new AwsAlbKeyResolver(contextInfo);
        keyLocationResolver = Mockito.spy(keyLocationResolver);

        when(keyLocationResolver.getHttpGet()).thenReturn(simpleGet);

        when(simpleGet.get("https://localhost:8080/c2f80c8b-c05c-4068-af14-17299f7896b1"))
                .thenReturn(simpleResponse);

        when(simpleResponse.getBody()).thenReturn(AWS_ALB_KEY);

        when(signature.getHeaders()).thenReturn(headers);
        when(headers.getStringHeaderValue(JsonWebKey.KEY_ID_PARAMETER)).thenReturn("c2f80c8b-c05c-4068-af14-17299f7896b1");

        Key key = keyLocationResolver.resolveKey(signature, List.of());
        assertTrue(key instanceof ECPublicKey);
        // Confirm the cached key is returned
        Key key2 = keyLocationResolver.resolveKey(signature, List.of());
        assertTrue(key2 == key);
    }

}
