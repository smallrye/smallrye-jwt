/*
 *   Copyright 2020 Red Hat, Inc, and individual contributors.
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
package io.smallrye.jwt.build;

import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import io.smallrye.jwt.build.impl.JwtProviderImpl;
import io.smallrye.jwt.build.spi.JwtProvider;

public class JwtProviderTest {

    @Test
    public void testProvider() {
        JwtProvider provider = JwtProvider.provider();
        assertTrue(provider instanceof JwtProviderImpl);
        assertSame(provider, JwtProvider.provider());
    }
}
