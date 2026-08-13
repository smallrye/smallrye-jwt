/*
 *   Copyright 2026 Red Hat, Inc, and individual contributors.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
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

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import io.smallrye.jwt.auth.UnresolvableKeyException;
import io.smallrye.jwt.auth.principal.JwksHttpFetcher.Response;

class RemoteJwkSetTest {

    private static final String JWKS = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"1\",\"k\":\"AAECAwQFBgcICQoLDA0ODw\"}]}";

    @Test
    void maxAgeTakesPrecedenceOverExpires() {
        long now = 1_000_000L;
        assertEquals(300_000L, RemoteJwkSet.getCacheLifeMillis(new Response(JWKS, "max-age=300", now + 60_000L), now));
        assertEquals(300_000L,
                RemoteJwkSet.getCacheLifeMillis(new Response(JWKS, "public, max-age=300, must-revalidate", 0), now));
        assertEquals(300_000L, RemoteJwkSet.getCacheLifeMillis(new Response(JWKS, "Max-Age = \"300\"", 0), now));
    }

    @Test
    void expiresIsUsedWithoutMaxAge() {
        long now = 1_000_000L;
        assertEquals(60_000L, RemoteJwkSet.getCacheLifeMillis(new Response(JWKS, null, now + 60_000L), now));
        assertEquals(60_000L, RemoteJwkSet.getCacheLifeMillis(new Response(JWKS, "no-transform", now + 60_000L), now));
        assertEquals(60_000L, RemoteJwkSet.getCacheLifeMillis(new Response(JWKS, "max-age=abc", now + 60_000L), now));
    }

    @Test
    void noUsableHeaders() {
        long now = 1_000_000L;
        assertEquals(0L, RemoteJwkSet.getCacheLifeMillis(new Response(JWKS, null, 0), now));
        assertEquals(0L, RemoteJwkSet.getCacheLifeMillis(new Response(JWKS, "max-age=0", 0), now));
        assertEquals(-60_000L, RemoteJwkSet.getCacheLifeMillis(new Response(JWKS, "no-store", now - 60_000L), now));
    }

    @Test
    void shortMaxAgeOverridesRefreshInterval() throws Exception {
        // the configured interval is 60 minutes, the endpoint advertises 1 second
        AtomicInteger fetches = new AtomicInteger();
        RemoteJwkSet jwkSet = remoteJwkSet(fetches, "max-age=1", 0);

        assertEquals("1", jwkSet.getKeys().get(0).keyId());
        assertEquals(1, fetches.get());
        assertEquals("1", jwkSet.getKeys().get(0).keyId());
        assertEquals(1, fetches.get());

        Thread.sleep(1100);
        assertEquals("1", jwkSet.getKeys().get(0).keyId());
        assertEquals(2, fetches.get());
    }

    @Test
    void refreshIntervalIsUsedWithoutCachingHeaders() throws Exception {
        AtomicInteger fetches = new AtomicInteger();
        RemoteJwkSet jwkSet = remoteJwkSet(fetches, null, 0);

        assertEquals("1", jwkSet.getKeys().get(0).keyId());
        Thread.sleep(1100);
        assertEquals("1", jwkSet.getKeys().get(0).keyId());
        assertEquals(1, fetches.get());
    }

    private static RemoteJwkSet remoteJwkSet(AtomicInteger fetches, String cacheControl, long expires)
            throws UnresolvableKeyException {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("https://localhost/jwks", "issuer");
        contextInfo.setJwksRefreshInterval(60);
        JwksHttpFetcher fetcher = new JwksHttpFetcher(contextInfo) {
            @Override
            Response fetchResponse(String location) throws IOException {
                fetches.incrementAndGet();
                return new Response(JWKS, cacheControl, expires);
            }
        };
        return new RemoteJwkSet(contextInfo.getPublicKeyLocation(), contextInfo, fetcher);
    }
}
