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

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.List;

import jakarta.json.Json;

import org.eclipse.microprofile.jwt.Claims;
import org.junit.jupiter.api.Test;

class JwtClaimTypeVerifierTest {
    @Test
    void sub() {
        Jwt.claim(Claims.sub, "1");
        assertThrows(IllegalArgumentException.class, () -> Jwt.claim(Claims.sub, 1), "IllegalArgumentException is expected");
    }

    @Test
    void iss() {
        Jwt.claim(Claims.iss, "1");
        assertThrows(IllegalArgumentException.class, () -> Jwt.claim(Claims.iss, 1), "IllegalArgumentException is expected");
    }

    @Test
    void upn() {
        Jwt.claim(Claims.upn, "1");
        assertThrows(IllegalArgumentException.class, () -> Jwt.claim(Claims.upn, 1), "IllegalArgumentException is expected");
    }

    @Test
    void jti() {
        Jwt.claim(Claims.jti, "1");
        assertThrows(IllegalArgumentException.class, () -> Jwt.claim(Claims.jti, 1), "IllegalArgumentException is expected");
    }

    @Test
    void preferredUserName() {
        Jwt.claim(Claims.preferred_username, "1");
        assertThrows(IllegalArgumentException.class, () -> Jwt.claim(Claims.preferred_username, 1),
                "IllegalArgumentException is expected");
    }

    @Test
    void iat() {
        Jwt.claim(Claims.iat, Instant.now().getEpochSecond());
        Jwt.claim(Claims.iat, Instant.now());
        Jwt.claim(Claims.iat, 1705105035.125D);
        assertThrows(IllegalArgumentException.class, () -> Jwt.claim(Claims.iat, "1"), "IllegalArgumentException is expected");
    }

    @Test
    void auth_time() {
        Jwt.claim(Claims.auth_time, Instant.now().getEpochSecond());
        Jwt.claim(Claims.auth_time, Instant.now());
        Jwt.claim(Claims.auth_time, 1704986861.532D);
        assertThrows(IllegalArgumentException.class, () -> Jwt.claim(Claims.auth_time, "1"),
                "IllegalArgumentException is expected");
    }

    @Test
    void exp() {
        Jwt.claim(Claims.exp, Instant.now().getEpochSecond());
        Jwt.claim(Claims.exp, Instant.now());
        Jwt.claim(Claims.exp, 1712762861.532D);
        assertThrows(IllegalArgumentException.class, () -> Jwt.claim(Claims.exp, "1"), "IllegalArgumentException is expected");
    }

    @Test
    void aud() {
        Jwt.claim(Claims.aud, "1");
        Jwt.claim(Claims.aud, List.of("1"));
        Jwt.claim(Claims.aud, Json.createArrayBuilder().add("1").build());
        assertThrows(IllegalArgumentException.class, () -> Jwt.claim(Claims.aud, 1), "IllegalArgumentException is expected");
        assertThrows(IllegalArgumentException.class, () -> Jwt.claim(Claims.aud, List.of(1)),
                "IllegalArgumentException is expected");
        assertThrows(IllegalArgumentException.class, () -> Jwt.claim(Claims.aud, Json.createArrayBuilder().add(1).build()),
                "IllegalArgumentException is expected");
    }

    @Test
    void groups() {
        Jwt.claim(Claims.groups, "1");
        Jwt.claim(Claims.groups, List.of("1"));
        Jwt.claim(Claims.groups, Json.createArrayBuilder().add("1").build());
        assertThrows(IllegalArgumentException.class, () -> Jwt.claim(Claims.groups, 1), "IllegalArgumentException is expected");
        assertThrows(IllegalArgumentException.class, () -> Jwt.claim(Claims.groups, List.of(1)),
                "IllegalArgumentException is expected");
        assertThrows(IllegalArgumentException.class, () -> Jwt.claim(Claims.groups, Json.createArrayBuilder().add(1).build()),
                "IllegalArgumentException is expected");
    }
}
