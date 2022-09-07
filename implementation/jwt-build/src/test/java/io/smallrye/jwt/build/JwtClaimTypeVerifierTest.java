/*
 *   Copyright 2021 Red Hat, Inc, and individual contributors.
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

import static org.junit.Assert.assertThrows;

import java.time.Instant;
import java.util.Arrays;

import jakarta.json.Json;

import org.eclipse.microprofile.jwt.Claims;
import org.junit.Test;

public class JwtClaimTypeVerifierTest {

    @Test
    public void testSub() {
        Jwt.claim(Claims.sub, "1");
        assertThrows("IllegalArgumentException is expected", IllegalArgumentException.class,
                () -> Jwt.claim(Claims.sub, 1));
    }

    @Test
    public void testIss() {
        Jwt.claim(Claims.iss, "1");
        assertThrows("IllegalArgumentException is expected", IllegalArgumentException.class,
                () -> Jwt.claim(Claims.iss, 1));
    }

    @Test
    public void testUpn() {
        Jwt.claim(Claims.upn, "1");
        assertThrows("IllegalArgumentException is expected", IllegalArgumentException.class,
                () -> Jwt.claim(Claims.upn, 1));
    }

    @Test
    public void testJti() {
        Jwt.claim(Claims.jti, "1");
        assertThrows("IllegalArgumentException is expected", IllegalArgumentException.class,
                () -> Jwt.claim(Claims.jti, 1));
    }

    @Test
    public void testPreferredUserName() {
        Jwt.claim(Claims.preferred_username, "1");
        assertThrows("IllegalArgumentException is expected", IllegalArgumentException.class,
                () -> Jwt.claim(Claims.preferred_username, 1));
    }

    @Test
    public void testIat() {
        Jwt.claim(Claims.iat, Instant.now().getEpochSecond());
        Jwt.claim(Claims.iat, Instant.now());
        assertThrows("IllegalArgumentException is expected", IllegalArgumentException.class,
                () -> Jwt.claim(Claims.iat, "1"));
    }

    @Test
    public void testExp() {
        Jwt.claim(Claims.exp, Instant.now().getEpochSecond());
        Jwt.claim(Claims.exp, Instant.now());
        assertThrows("IllegalArgumentException is expected", IllegalArgumentException.class,
                () -> Jwt.claim(Claims.exp, "1"));
    }

    @Test
    public void testAud() {
        Jwt.claim(Claims.aud, "1");
        Jwt.claim(Claims.aud, Arrays.asList("1"));
        Jwt.claim(Claims.aud, Json.createArrayBuilder().add("1").build());
        assertThrows("IllegalArgumentException is expected", IllegalArgumentException.class,
                () -> Jwt.claim(Claims.aud, 1));
        assertThrows("IllegalArgumentException is expected", IllegalArgumentException.class,
                () -> Jwt.claim(Claims.aud,
                        Arrays.asList(1)));
        assertThrows("IllegalArgumentException is expected", IllegalArgumentException.class,
                () -> Jwt.claim(Claims.aud, Json.createArrayBuilder().add(1).build()));
    }

    @Test
    public void testGroups() {
        Jwt.claim(Claims.groups, "1");
        Jwt.claim(Claims.groups, Arrays.asList("1"));
        Jwt.claim(Claims.groups, Json.createArrayBuilder().add("1").build());
        assertThrows("IllegalArgumentException is expected", IllegalArgumentException.class,
                () -> Jwt.claim(Claims.groups, 1));
        assertThrows("IllegalArgumentException is expected", IllegalArgumentException.class,
                () -> Jwt.claim(Claims.groups,
                        Arrays.asList(1)));
        assertThrows("IllegalArgumentException is expected", IllegalArgumentException.class,
                () -> Jwt.claim(Claims.groups, Json.createArrayBuilder().add(1).build()));
    }

}
