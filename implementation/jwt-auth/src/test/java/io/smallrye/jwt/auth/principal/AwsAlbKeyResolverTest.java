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

import java.security.Key;
import java.security.interfaces.ECPublicKey;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.auth.UnresolvableKeyException;
import io.smallrye.jwt.util.KeyUtils;

class AwsAlbKeyResolverTest {

    private static final String AWS_ALB_KEY = "-----BEGIN PUBLIC KEY-----"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjPHY1j9umvc8nZEswOzs+lPpLKLn"
            + "qCBqvyZGJfBlXapmtGiqYEwpIqh/lZdkr4wDii7CP1DzIUSHONbc+jufiQ=="
            + "-----END PUBLIC KEY-----";

    @Test
    void loadAwsAlbVerificationKey() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(
                "https://localhost:8080",
                "https://cognito-idp.eu-central-1.amazonaws.com");
        contextInfo.setSignatureAlgorithm(Set.of(SignatureAlgorithm.ES256));

        AwsAlbKeyResolver keyLocationResolver = new AwsAlbKeyResolver(contextInfo) {
            @Override
            protected Key retrieveKey(String kid) throws UnresolvableKeyException {
                try {
                    return KeyUtils.decodePublicKey(AWS_ALB_KEY, SignatureAlgorithm.ES256);
                } catch (Exception e) {
                    throw new UnresolvableKeyException("Failed to decode key", e);
                }
            }
        };

        Key key = keyLocationResolver
                .resolveKey(new JsonWebSignatureImpl(new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("c2f80c8b-c05c-4068-af14-17299f7896b1").build(),
                        new JWTClaimsSet.Builder().build()), null));
        assertTrue(key instanceof ECPublicKey);
        // Confirm the cached key is returned
        Key key2 = keyLocationResolver
                .resolveKey(new JsonWebSignatureImpl(new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("c2f80c8b-c05c-4068-af14-17299f7896b1").build(),
                        new JWTClaimsSet.Builder().build()), null));
        assertTrue(key2 == key);
    }

}
