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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;
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

    @Test
    void failedFetchWithEmptyCacheFails() throws Exception {
        AtomicInteger fetches = new AtomicInteger();
        AtomicBoolean fail = new AtomicBoolean(true);
        RemoteJwkSet jwkSet = remoteJwkSet(fetches, "max-age=1", 0, 10, fail, JWKS);

        IOException ex = assertThrows(IOException.class, jwkSet::getKeys);
        assertEquals("Connection failed", ex.getMessage());
    }

    @Test
    void failedRefreshWithoutRetainDurationFails() throws Exception {
        AtomicInteger fetches = new AtomicInteger();
        AtomicBoolean fail = new AtomicBoolean(false);
        RemoteJwkSet jwkSet = remoteJwkSet(fetches, "max-age=1", 0, 0, fail, JWKS);

        assertEquals("1", jwkSet.getKeys().get(0).keyId());

        fail.set(true);
        Thread.sleep(1100);
        assertThrows(IOException.class, jwkSet::getKeys);
    }

    @Test
    void failedRefreshWithRetainDurationKeepsCachedKeys() throws Exception {
        AtomicInteger fetches = new AtomicInteger();
        AtomicBoolean fail = new AtomicBoolean(false);
        RemoteJwkSet jwkSet = remoteJwkSet(fetches, "max-age=1", 0, 10, fail, JWKS);

        assertEquals("1", jwkSet.getKeys().get(0).keyId());
        assertEquals(1, fetches.get());

        fail.set(true);
        Thread.sleep(1100);
        assertEquals("1", jwkSet.getKeys().get(0).keyId());
        assertEquals(2, fetches.get());
        // the keys are retained for 10 minutes, the endpoint is not called again
        assertEquals("1", jwkSet.getKeys().get(0).keyId());
        assertEquals(2, fetches.get());
    }

    @Test
    void malformedContentIsReportedAsParseFailureAndKeepsCachedKeys() throws Exception {
        AtomicInteger fetches = new AtomicInteger();
        AtomicBoolean fail = new AtomicBoolean(false);
        RemoteJwkSet jwkSet = remoteJwkSet(fetches, "max-age=1", 0, 10, fail, "not a JWK set");

        // the first fetch returns the valid JWK set, the second one returns the malformed content
        assertEquals("1", jwkSet.getKeys().get(0).keyId());

        Thread.sleep(1100);
        assertEquals("1", jwkSet.getKeys().get(0).keyId());
        assertEquals(2, fetches.get());

        // the parse failure is reported as such when the cache is empty
        AtomicInteger moreFetches = new AtomicInteger(1);
        assertThrows(RemoteJwkSet.JwksParseException.class, remoteJwkSet(moreFetches, null, 0, 0, fail, "{}")::getKeys);
    }

    @Test
    void forcedRefreshIsRateLimited() throws Exception {
        AtomicInteger fetches = new AtomicInteger();
        RemoteJwkSet jwkSet = remoteJwkSet(fetches, null, 0);

        assertEquals("1", jwkSet.getKeys().get(0).keyId());
        assertEquals(1, fetches.get());

        // a refresh is skipped if the keys have just been loaded
        Thread.sleep(400);
        assertTrue(jwkSet.forcedRefresh());
        assertEquals(2, fetches.get());

        // a second forced refresh inside the forced refresh interval does not call the endpoint
        Thread.sleep(400);
        assertTrue(jwkSet.forcedRefresh());
        assertEquals(2, fetches.get());
    }

    private static RemoteJwkSet remoteJwkSet(AtomicInteger fetches, String cacheControl, long expires)
            throws UnresolvableKeyException {
        return remoteJwkSet(fetches, cacheControl, expires, 0, new AtomicBoolean(false), JWKS);
    }

    /**
     * The fetcher returns the JWK set on the first fetch and 'secondBody' afterwards, or fails if 'fail' is set.
     */
    private static RemoteJwkSet remoteJwkSet(AtomicInteger fetches, String cacheControl, long expires,
            int retainOnErrorMinutes, AtomicBoolean fail, String secondBody) throws UnresolvableKeyException {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo("https://localhost/jwks", "issuer");
        contextInfo.setJwksRefreshInterval(60);
        contextInfo.setJwksRetainCacheOnErrorDuration(retainOnErrorMinutes);
        JwksHttpFetcher fetcher = new JwksHttpFetcher(contextInfo) {
            @Override
            Response fetchResponse(String location) throws IOException {
                int attempt = fetches.incrementAndGet();
                if (fail.get()) {
                    throw new IOException("Connection failed");
                }
                return new Response(attempt == 1 ? JWKS : secondBody, cacheControl, expires);
            }
        };
        return new RemoteJwkSet(contextInfo.getPublicKeyLocation(), contextInfo, fetcher);
    }
}
