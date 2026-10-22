package io.smallrye.jwt.auth.principal;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

import io.smallrye.jwk.JsonWebKey;
import io.smallrye.jwk.JsonWebKeyException;
import io.smallrye.jwk.JsonWebKeySet;
import io.smallrye.jwt.auth.UnresolvableKeyException;

/**
 * Manages fetching and caching of a remote JWK set from an HTTPS endpoint.
 * Encapsulates cache duration, forced refresh cooldown, and retain-on-error behavior.
 * The cached keys are retained on error whether the endpoint can not be reached or returns content
 * which is not a valid JWK set.
 */
class RemoteJwkSet {

    private final String location;
    private final JwksHttpFetcher fetcher;
    private final long cacheDurationMillis;
    private final long retainOnErrorDurationMillis;
    private final long forcedRefreshIntervalMillis;

    // A refresh is skipped if the keys have been loaded less than this many milliseconds ago
    private static final long REFRESH_REPRIEVE_THRESHOLD_MILLIS = 300L;

    private volatile Cache cache = new Cache(Collections.emptyList(), 0);
    private long lastForcedRefreshTime;
    private final Object forcedRefreshLock = new Object();
    // Stops multiple threads from refreshing in parallel
    private final ReentrantLock refreshLock = new ReentrantLock();

    RemoteJwkSet(String location, JWTAuthContextInfo authContextInfo) throws UnresolvableKeyException {
        this(location, authContextInfo, new JwksHttpFetcher(authContextInfo));
    }

    RemoteJwkSet(String location, JWTAuthContextInfo authContextInfo, JwksHttpFetcher fetcher) {
        this.location = location;
        this.fetcher = fetcher;
        this.cacheDurationMillis = authContextInfo.getJwksRefreshInterval().longValue() * 60L * 1000L;
        this.retainOnErrorDurationMillis = authContextInfo.getJwksRetainCacheOnErrorDuration() * 60L * 1000L;
        this.forcedRefreshIntervalMillis = authContextInfo.getForcedJwksRefreshInterval() * 60L * 1000L;
    }

    List<JsonWebKey> getKeys() throws IOException {
        final long now = System.currentTimeMillis();
        Cache c = cache;
        if (c.expiry > now) {
            // common case: keys are still good
            return c.keys;
        }
        if (!refreshLock.tryLock()) {
            // another thread is already refreshing, use the cached keys for now, if any
            if (!c.keys.isEmpty()) {
                return c.keys;
            }
            refreshLock.lock();
        }
        // keys are expired and no other thread is refreshing them
        try {
            refresh();
            c = cache;
        } catch (IOException e) {
            if (retainOnErrorDurationMillis > 0 && !c.keys.isEmpty()) {
                // keep using the cached keys until the retain duration is over
                cache = c = new Cache(c.keys, now + retainOnErrorDurationMillis, c.created);
                PrincipalLogging.log.failedToRefreshJWKSet(e);
            } else {
                throw e;
            }
        } finally {
            refreshLock.unlock();
        }
        return c.keys;
    }

    boolean forcedRefresh() {
        synchronized (forcedRefreshLock) {
            long now = System.currentTimeMillis();
            if (lastForcedRefreshTime == 0 || now > lastForcedRefreshTime + forcedRefreshIntervalMillis) {
                lastForcedRefreshTime = now;
                try {
                    PrincipalLogging.log.kidIsNotAvailableRefreshingJWKSet();
                    refresh();
                } catch (IOException e) {
                    PrincipalLogging.log.failedToRefreshJWKSet(e);
                    return false;
                }
            } else {
                PrincipalLogging.log.matchingKidIsNotAvailableButJWTSRefreshed(
                        (int) (forcedRefreshIntervalMillis / 60000));
            }
        }
        return true;
    }

    void refresh() throws IOException {
        refreshLock.lock();
        try {
            Cache c = cache;
            if (System.currentTimeMillis() - c.created < REFRESH_REPRIEVE_THRESHOLD_MILLIS && !c.keys.isEmpty()) {
                // the keys have just been loaded
                return;
            }
            JwksHttpFetcher.Response response = fetcher.fetchResponse(location);
            try {
                List<JsonWebKey> keys = JsonWebKeySet.parse(response.body).keys();
                long now = System.currentTimeMillis();
                long cacheLifeMillis = getCacheLifeMillis(response, now);
                if (cacheLifeMillis <= 0) {
                    cacheLifeMillis = cacheDurationMillis;
                }
                cache = new Cache(keys, now + cacheLifeMillis);
            } catch (JsonWebKeyException e) {
                throw new JwksParseException("Failed to parse JWKS from " + location, e);
            }
        } finally {
            refreshLock.unlock();
        }
    }

    /**
     * Cache life as advertised by the JWKS endpoint: 'Cache-Control' 'max-age' takes precedence over 'Expires'.
     * Returns 0 or a negative value if the response carries no usable caching headers.
     * This matches the jose4j HttpsJwks logic which was used before the migration to Nimbus JOSE+JWT.
     */
    static long getCacheLifeMillis(JwksHttpFetcher.Response response, long now) {
        long maxAge = getMaxAgeSeconds(response.cacheControl);
        if (maxAge >= 0) {
            return maxAge * 1000L;
        }
        return response.expires > 0 ? response.expires - now : 0;
    }

    // Returns -1 if the header has no parseable 'max-age' directive
    static long getMaxAgeSeconds(String cacheControl) {
        if (cacheControl == null) {
            return -1;
        }
        for (String directive : cacheControl.split(",")) {
            String[] pair = directive.trim().split("=", 2);
            if (pair.length == 2 && pair[0].trim().equalsIgnoreCase("max-age")) {
                try {
                    return Long.parseLong(pair[1].trim().replace("\"", ""));
                } catch (NumberFormatException e) {
                    return -1;
                }
            }
        }
        return -1;
    }

    /**
     * Indicates that the JWKS content could not be parsed, as opposed to a network failure.
     */
    static class JwksParseException extends IOException {

        private static final long serialVersionUID = 1L;

        JwksParseException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private static class Cache {
        private final List<JsonWebKey> keys;
        private final long expiry;
        private final long created;

        private Cache(List<JsonWebKey> keys, long expiry) {
            this(keys, expiry, System.currentTimeMillis());
        }

        private Cache(List<JsonWebKey> keys, long expiry, long created) {
            this.keys = keys;
            this.expiry = expiry;
            this.created = created;
        }
    }

    String getLocation() {
        return location;
    }

    JwksHttpFetcher getFetcher() {
        return fetcher;
    }
}
