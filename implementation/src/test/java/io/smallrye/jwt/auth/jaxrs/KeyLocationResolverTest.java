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
package io.smallrye.jwt.auth.jaxrs;

import static java.util.Collections.emptyList;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.UnresolvableKeyException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mock;

import io.smallrye.jwt.auth.principal.KeyLocationResolver;

public class KeyLocationResolverTest {

    @Mock
    JsonWebSignature jsonWebSignature;

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Test
    public void testLoadingPublicKeyWithWrongResourceLocation() throws Exception {

        expectedEx.expect(UnresolvableKeyException.class);

        KeyLocationResolver keyLocationResolver = new KeyLocationResolver("wrong_location.pem");
        keyLocationResolver.resolveKey(jsonWebSignature, emptyList());
    }
}
