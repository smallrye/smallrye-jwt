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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

import org.jose4j.http.Get;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.UnresolvableKeyException;

import io.smallrye.jwt.KeyFormat;
import io.smallrye.jwt.util.KeyUtils;
import io.smallrye.jwt.util.ResourceUtils;
import io.smallrye.jwt.util.ResourceUtils.UrlStreamResolver;

/**
 * This implements the MP-JWT 1.1 mp.jwt.verify.publickey.location config property resolution logic
 */
public class AbstractKeyLocationResolver {

    private static final String HTTP_SCHEME = "http:";
    private static final String HTTPS_SCHEME = "https:";

    protected Key key;

    // The 'jsonWebKeys' and 'httpsJwks' fields represent the JWK key content and are mutually exclusive.
    // 'httpsJwks' only deals with the HTTPS URL based JWK sets while 'jsonWebKeys' represents the JWK key(s)
    // loaded from the JWK set or single JWK key from the file system or class path or HTTP URL.
    protected List<JsonWebKey> jsonWebKeys;
    // 'httpsJwks' represents the JWK set loaded from the HTTPS URL.
    protected HttpsJwks httpsJwks;
    protected long lastForcedRefreshTime;
    protected Object forcedRefreshLock = new Object();

    protected JWTAuthContextInfo authContextInfo;

    public AbstractKeyLocationResolver(JWTAuthContextInfo authContextInfo) throws UnresolvableKeyException {
        this.authContextInfo = authContextInfo;
        PrincipalLogging.log.authContextInfo(authContextInfo);
    }

    protected static boolean isMatchingJwkAvailable(List<JsonWebKey> keys, String kid) {
        if (kid != null) {
            for (JsonWebKey currentJwk : keys) {
                if (kid.equals(currentJwk.getKeyId())) {
                    return true;
                }
            }
        }
        return false;
    }

    protected static void verifyKid(JsonWebStructure jws, String expectedKid) throws UnresolvableKeyException {
        if (expectedKid != null) {
            String kid = getKid(jws);
            if (kid != null && !kid.equals(expectedKid)) {
                PrincipalLogging.log.invalidTokenKidHeader(kid, expectedKid);
                throw PrincipalMessages.msg.invalidTokenKid();
            }
        }
    }

    protected static String getKid(JsonWebStructure jws) {
        return jws.getHeaders().getStringHeaderValue(JsonWebKey.KEY_ID_PARAMETER);
    }

    protected HttpsJwks initializeHttpsJwks(String location)
            throws IOException {
        PrincipalLogging.log.tryCreateKeyFromHttpsJWKS();
        HttpsJwks theHttpsJwks = getHttpsJwks(location);
        Get httpGet = getHttpGet();
        if (location.startsWith(HTTPS_SCHEME)) {
            if (authContextInfo.isTlsTrustAll()) {
                httpGet.setHostnameVerifier(new TrustAllHostnameVerifier());
            } else if (authContextInfo.getTlsTrustedHosts() != null) {
                httpGet.setHostnameVerifier(new TrustedHostsHostnameVerifier(authContextInfo.getTlsTrustedHosts()));
            }
            if (authContextInfo.getTlsCertificatePath() != null) {
                httpGet.setTrustedCertificates(loadPEMCertificate(readKeyContent(authContextInfo.getTlsCertificatePath())));
            }
        }
        if (authContextInfo.getHttpProxyHost() != null) {
            httpGet.setHttpProxy(new Proxy(Proxy.Type.HTTP,
                    new InetSocketAddress(authContextInfo.getHttpProxyHost(), authContextInfo.getHttpProxyPort())));
        }
        theHttpsJwks.setSimpleHttpGet(httpGet);
        return theHttpsJwks;
    }

    protected HttpsJwks getHttpsJwks(String location) {
        HttpsJwks theHttpsJwks = new HttpsJwks(location);
        theHttpsJwks.setDefaultCacheDuration(authContextInfo.getJwksRefreshInterval().longValue() * 60L);
        return theHttpsJwks;
    }

    protected Get getHttpGet() {
        return new Get();
    }

    protected boolean isHttpsJwksInitialized(String keyLocation)
            throws IOException {
        if (mayBeFormat(KeyFormat.JWK) && keyLocation != null
                && (keyLocation.startsWith(HTTPS_SCHEME) || keyLocation.startsWith(HTTP_SCHEME))) {
            httpsJwks = initializeHttpsJwks(keyLocation);
            try {
                httpsJwks.refresh();
                return true;
            } catch (JoseException ex) {
                httpsJwks = null;
            }
        }
        return false;
    }

    protected boolean forcedHttpsJwksRefresh() {
        synchronized (forcedRefreshLock) {
            final long now = System.currentTimeMillis();
            if (lastForcedRefreshTime == 0
                    || now > lastForcedRefreshTime + authContextInfo.getForcedJwksRefreshInterval() * 60 * 1000) {
                lastForcedRefreshTime = now;
                try {
                    PrincipalLogging.log.kidIsNotAvailableRefreshingJWKSet();
                    httpsJwks.refresh();
                } catch (JoseException | IOException e) {
                    PrincipalLogging.log.failedToRefreshJWKSet(e);
                    return false;
                }
            } else {
                PrincipalLogging.log.matchingKidIsNotAvailableButJWTSRefreshed(authContextInfo.getForcedJwksRefreshInterval());
            }
        }
        return true;
    }

    protected String readKeyContent(String keyLocation) throws IOException {

        String content = ResourceUtils.readResource(keyLocation, getUrlResolver());
        if (content == null) {
            throw PrincipalMessages.msg.resourceNotFound(keyLocation);
        }
        return content;
    }

    protected UrlStreamResolver getUrlResolver() {
        return new UrlStreamResolver();
    }

    protected static JsonWebKey getJsonWebKey(String kid, List<JsonWebKey> keys, String algo) {
        PrincipalLogging.log.tryCreateKeyFromJWKS();

        try {
            if (kid != null) {
                for (JsonWebKey currentJwk : keys) {
                    if (kid.equals(currentJwk.getKeyId())
                            && (currentJwk.getAlgorithm() == null || algo.equals(currentJwk.getAlgorithm()))) {
                        return currentJwk;
                    }
                }
            }
            // if JWK set contains a single JWK only then try to use it
            // but only if 'kid' is not set in both the token and this JWK
            if (keys.size() == 1 && (kid == null || keys.get(0).getKeyId() == null)
                    && (keys.get(0).getAlgorithm() == null || algo.equals(keys.get(0).getAlgorithm()))) {
                return keys.get(0);
            }
        } catch (Exception e) {
            PrincipalLogging.log.failedToCreateKeyFromJWKS(e);
        }
        return null;
    }

    boolean mayBeFormat(KeyFormat format) {
        return isFormat(format) || authContextInfo.getKeyFormat() == KeyFormat.ANY;
    }

    boolean isFormat(KeyFormat format) {
        return authContextInfo.getKeyFormat() == format;
    }

    protected static void reportLoadKeyException(String keyContent, String keyLocation, Exception e)
            throws UnresolvableKeyException {
        if (keyContent != null) {
            throw PrincipalMessages.msg.failedToLoadKey(e);
        } else {
            throw PrincipalMessages.msg
                    .failedToLoadKeyFromLocation(keyLocation, e);
        }
    }

    protected static void reportUnresolvableKeyException(String keyContent, String keyLocation)
            throws UnresolvableKeyException {
        if (keyContent != null) {
            throw PrincipalMessages.msg.failedToLoadKeyWhileResolving();
        } else {
            throw PrincipalMessages.msg
                    .failedToLoadKeyFromLocationWhileResolving(keyLocation);
        }
    }

    protected JsonWebKey tryAsJwk(JsonWebStructure jws, String algo) throws UnresolvableKeyException {
        String kid = getKid(jws);

        if (httpsJwks != null) {
            return getHttpsJwk(kid, algo);
        } else if (jsonWebKeys != null) {
            return getJsonWebKey(kid, jsonWebKeys, algo);
        } else {
            return null;
        }
    }

    protected JsonWebKey getHttpsJwk(String kid, String algo) {
        PrincipalLogging.log.tryCreateKeyFromHttpsJWKS();

        try {
            List<JsonWebKey> theKeys = httpsJwks.getJsonWebKeys();
            JsonWebKey theKey = getJsonWebKey(kid, theKeys, algo);
            if (theKey != null || isMatchingJwkAvailable(theKeys, kid)) {
                return theKey;
            }
        } catch (Exception e) {
            PrincipalLogging.log.failedToCreateKeyFromJWKSet(e);
        }

        forcedHttpsJwksRefresh();

        try {
            PrincipalLogging.log.tryCreateKeyFromJWKSAfterRefresh();
            return getJsonWebKey(kid, httpsJwks.getJsonWebKeys(), algo);
        } catch (Exception e) {
            PrincipalLogging.log.failedToCreateKeyFromJWKSAfterRefresh(e);
        }
        return null;
    }

    protected JsonWebKey getJsonWebKey(String kid, String algo) {
        return getJsonWebKey(kid, jsonWebKeys, algo);
    }

    protected JsonWebKey tryJWKContent(final String content, String keyId, String algo, boolean encoded) {
        jsonWebKeys = KeyUtils.loadJsonWebKeys(content);
        JsonWebKey jwk = null;
        if (jsonWebKeys != null && keyId != null) {
            jwk = getJsonWebKey(keyId, jsonWebKeys, algo);
            if (jwk != null) {
                if (encoded) {
                    PrincipalLogging.log.keyCreatedFromEncodedJWKKeyOrJWKKeySet();
                } else {
                    PrincipalLogging.log.keyCreatedFromJWKKeyOrJWKKeySet();
                }
            }
        }
        return jwk;
    }

    protected JsonWebKey loadFromJwk(String content, String keyId, String algo) {
        JsonWebKey jwk = null;
        if (mayBeFormat(KeyFormat.JWK)) {
            PrincipalLogging.log.checkKeyContentIsJWKKeyOrJWKKeySet();
            jwk = tryJWKContent(content, keyId, algo, false);
            if (jwk != null || isFormat(KeyFormat.JWK)) {
                return jwk;
            }
        }
        if (jsonWebKeys == null && mayBeFormat(KeyFormat.JWK_BASE64URL)) {
            // Try Base64 Decoding
            try {
                PrincipalLogging.log.checkKeyContentIsBase64EncodedJWKKeyOrJWKKeySet();
                content = new String(Base64.getUrlDecoder().decode(content.getBytes(StandardCharsets.UTF_8)),
                        StandardCharsets.UTF_8);
                jwk = tryJWKContent(content, keyId, algo, true);
            } catch (IllegalArgumentException e) {
                PrincipalLogging.log.unableToDecodeContentUsingBase64(e);
            }
        }
        return jwk;
    }

    protected Key getSecretKeyFromJwk(JsonWebKey jwk) {
        if (jwk instanceof OctetSequenceJsonWebKey) {
            return ((OctetSequenceJsonWebKey) jwk).getKey();
        }
        return null;
    }

    protected X509Certificate loadPEMCertificate(String content) {
        PrincipalLogging.log.checkKeyContentIsBase64EncodedPEMCertificate();
        X509Certificate cert = null;
        try {
            cert = KeyUtils.getCertificate(content);
            PrincipalLogging.log.publicKeyCreatedFromEncodedPEMCertificate();
        } catch (Exception e) {
            PrincipalLogging.log.keyContentIsNotValidEncodedPEMCertificate(e);
        }
        return cert;
    }

    static class TrustAllHostnameVerifier implements HostnameVerifier {

        @Override
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    }

    static class TrustedHostsHostnameVerifier implements HostnameVerifier {

        Set<String> hosts;

        TrustedHostsHostnameVerifier(Set<String> hosts) {
            this.hosts = hosts;
        }

        @Override
        public boolean verify(String hostname, SSLSession session) {
            return hosts.contains(hostname);
        }

    }
}
