package io.smallrye.jwt.auth.principal;

import java.io.IOException;
import java.net.URI;
import java.security.Key;
import java.time.Duration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.jose4j.http.Get;
import org.jose4j.http.SimpleGet;
import org.jose4j.http.SimpleResponse;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.jose4j.lang.UnresolvableKeyException;

import io.smallrye.jwt.auth.principal.AbstractKeyLocationResolver.TrustAllHostnameVerifier;
import io.smallrye.jwt.auth.principal.AbstractKeyLocationResolver.TrustedHostsHostnameVerifier;
import io.smallrye.jwt.util.KeyUtils;
import io.smallrye.jwt.util.ResourceUtils;

public class AwsAlbKeyResolver implements VerificationKeyResolver {
    private JWTAuthContextInfo authContextInfo;
    private long cacheTimeToLive;
    private Map<String, CacheEntry> keys = new HashMap<>();
    private AtomicInteger size = new AtomicInteger();

    public AwsAlbKeyResolver(JWTAuthContextInfo authContextInfo) throws UnresolvableKeyException {
        var publicKeyLocation = authContextInfo.getPublicKeyLocation();
        if (publicKeyLocation == null) {
            throw PrincipalMessages.msg.nullKeyLocation();
        }
        if (containsSubPath(publicKeyLocation)) {
            throw PrincipalMessages.msg.subPathNotAllowed();
        }
        this.authContextInfo = authContextInfo;
        this.cacheTimeToLive = Duration.ofMinutes(authContextInfo.getKeyCacheTimeToLive()).toMillis();
    }

    static String removeEndingSlash(String uri){
        if(!uri.endsWith("/") || uri.length() == 1){
            return uri;
        }
        var length = uri.length();
        return uri.substring(0, length - 1);
    }

    static boolean containsSubPath(String publicKeyLocation) {
        var locationWithoutSlash = removeEndingSlash(publicKeyLocation);
        var uri = URI.create(locationWithoutSlash);
        return uri.getPath().contains("/");
    }

    @Override
    public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext) throws UnresolvableKeyException {
        String kid = jws.getHeaders().getStringHeaderValue(JsonWebKey.KEY_ID_PARAMETER);
        verifyKid(kid);

        CacheEntry entry = findValidCacheEntry(kid);
        if (entry != null) {
            return entry.key;
        } else if (prepareSpaceForNewCacheEntry()) {
            entry = new CacheEntry(retrieveKey(kid));
            keys.put(kid, entry);
            return entry.key;
        } else {
            return retrieveKey(kid);
        }

    }

    protected Key retrieveKey(String kid) throws UnresolvableKeyException {
        String keyLocation = authContextInfo.getPublicKeyLocation() + "/" + kid;
        SimpleResponse simpleResponse = null;
        try {
            simpleResponse = getHttpGet().get(keyLocation);
        } catch (IOException ex) {
            AbstractKeyLocationResolver.reportLoadKeyException(null, keyLocation, ex);
        }
        String keyContent = simpleResponse.getBody();
        try {
            return KeyUtils.decodePublicKey(keyContent, authContextInfo.getSignatureAlgorithm());
        } catch (Exception e) {
            AbstractKeyLocationResolver.reportUnresolvableKeyException(keyContent, keyLocation);
        }
        return null;
    }

    protected SimpleGet getHttpGet() throws UnresolvableKeyException {
        Get httpGet = new Get();
        if (authContextInfo.isTlsTrustAll()) {
            httpGet.setHostnameVerifier(new TrustAllHostnameVerifier());
        } else if (authContextInfo.getTlsTrustedHosts() != null) {
            httpGet.setHostnameVerifier(new TrustedHostsHostnameVerifier(authContextInfo.getTlsTrustedHosts()));
        }
        if (authContextInfo.getTlsCertificate() != null) {
            httpGet.setTrustedCertificates(
                    AbstractKeyLocationResolver.loadPEMCertificate(authContextInfo.getTlsCertificate()));
        } else if (authContextInfo.getTlsCertificatePath() != null) {
            httpGet.setTrustedCertificates(AbstractKeyLocationResolver.loadPEMCertificate(
                    readKeyContent(authContextInfo.getTlsCertificatePath())));
        }
        return httpGet;
    }

    protected String readKeyContent(String keyLocation) throws UnresolvableKeyException {
        try {
            String content = ResourceUtils.readResource(keyLocation);
            if (content == null) {
                throw PrincipalMessages.msg.resourceNotFound(keyLocation);
            }
            return content;
        } catch (IOException ex) {
            AbstractKeyLocationResolver.reportLoadKeyException(null, keyLocation, ex);
            return null;
        }
    }

    private void verifyKid(String kid) throws UnresolvableKeyException {
        if (kid == null) {
            throw PrincipalMessages.msg.nullKeyIdentifier();
        }
        String expectedKid = authContextInfo.getTokenKeyId();
        if (expectedKid != null && !kid.equals(expectedKid)) {
            PrincipalLogging.log.invalidTokenKidHeader(kid, expectedKid);
            throw PrincipalMessages.msg.invalidTokenKid();
        }
    }

    private void removeInvalidEntries() {
        long now = now();
        for (Iterator<Map.Entry<String, CacheEntry>> it = keys.entrySet().iterator(); it.hasNext();) {
            Map.Entry<String, CacheEntry> next = it.next();
            if (isEntryExpired(next.getValue(), now)) {
                it.remove();
                size.decrementAndGet();
            }
        }
    }

    private boolean prepareSpaceForNewCacheEntry() {
        int currentSize;
        do {
            currentSize = size.get();
            if (currentSize == authContextInfo.getKeyCacheSize()) {
                removeInvalidEntries();
                if (currentSize == authContextInfo.getKeyCacheSize()) {
                    return false;
                }
            }
        } while (!size.compareAndSet(currentSize, currentSize + 1));
        return true;
    }

    private CacheEntry findValidCacheEntry(String kid) {
        CacheEntry entry = keys.get(kid);
        if (entry != null) {
            long now = now();
            if (isEntryExpired(entry, now)) {
                // Entry has expired, remote introspection will be required
                entry = null;
                keys.remove(kid);
                size.decrementAndGet();
            }
        }
        return entry;
    }

    private boolean isEntryExpired(CacheEntry entry, long now) {
        return entry.createdTime + cacheTimeToLive < now;
    }

    private static long now() {
        return System.currentTimeMillis();
    }

    private static class CacheEntry {
        volatile Key key;
        long createdTime = System.currentTimeMillis();

        public CacheEntry(Key key) {
            this.key = key;
        }
    }
}
