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
import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

import java.security.PublicKey;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.Headers;
import org.jose4j.lang.UnresolvableKeyException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

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

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Test
    public void testLoadingPublicKeyWithWrongResourceLocation() throws Exception {

        expectedEx.expect(UnresolvableKeyException.class);

        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(new JWTAuthContextInfo("wrong_location.pem", null));
        keyLocationResolver.resolveKey(jsonWebSignature, emptyList());
    }

    @Test
    public void testHttpsKeyLocation() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("https://github.com/my_key.pem", "issuer");
        contextInfo.setJwksRefreshInterval(10);
        KeyLocationResolver keyLocationResolver = new KeyLocationResolver(contextInfo);
        keyLocationResolver = Mockito.spy(keyLocationResolver);
        Mockito.doReturn(key).when(keyLocationResolver).getHttpsJwk(Mockito.any());
        when(signature.getHeaders()).thenReturn(headers);
        when(headers.getStringHeaderValue(JsonWebKey.KEY_ID_PARAMETER)).thenReturn("1");
        assertEquals(key, keyLocationResolver.resolveKey(signature, emptyList()));
        assertNull(keyLocationResolver.verificationKey);
    }
}
