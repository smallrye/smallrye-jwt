package io.smallrye.jwt.auth.principal;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import io.smallrye.jwk.JsonWebKey;
import io.smallrye.jwk.JsonWebKeyException;
import io.smallrye.jwk.JsonWebKeySet;

/**
 * Manages fetching and caching of a remote JWK set from an HTTPS endpoint.
 * Encapsulates cache duration, forced refresh cooldown, and retain-on-error behavior.
 */
class RemoteJwkSet {

    private final String location;
    private final JwksHttpFetcher fetcher;
    private final long cacheDurationMillis;
    private final long retainOnErrorDurationMillis;
    private final long forcedRefreshIntervalMillis;

    private volatile List<JsonWebKey> cachedKeys = Collections.emptyList();
    private volatile long lastRefreshTime;
    private long lastForcedRefreshTime;
    private final Object forcedRefreshLock = new Object();

    RemoteJwkSet(String location, JWTAuthContextInfo authContextInfo) {
        this.location = location;
        this.fetcher = new JwksHttpFetcher(authContextInfo);
        this.cacheDurationMillis = authContextInfo.getJwksRefreshInterval().longValue() * 60L * 1000L;
        this.retainOnErrorDurationMillis = authContextInfo.getJwksRetainCacheOnErrorDuration() * 60L * 1000L;
        this.forcedRefreshIntervalMillis = authContextInfo.getForcedJwksRefreshInterval() * 60L * 1000L;
    }

    List<JsonWebKey> getKeys() {
        long now = System.currentTimeMillis();
        if (now < lastRefreshTime + cacheDurationMillis) {
            return cachedKeys;
        }
        try {
            refresh();
        } catch (IOException e) {
            if (retainOnErrorDurationMillis > 0 && !cachedKeys.isEmpty()
                    && now < lastRefreshTime + cacheDurationMillis + retainOnErrorDurationMillis) {
                PrincipalLogging.log.failedToRefreshJWKSet(e);
            } else {
                PrincipalLogging.log.failedToRefreshJWKSet(e);
            }
        }
        return cachedKeys;
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
        String content = fetcher.fetch(location);
        try {
            cachedKeys = JsonWebKeySet.parse(content).keys();
            lastRefreshTime = System.currentTimeMillis();
        } catch (JsonWebKeyException e) {
            throw new IOException("Failed to parse JWKS from " + location, e);
        }
    }

    String getLocation() {
        return location;
    }

    JwksHttpFetcher getFetcher() {
        return fetcher;
    }
}
