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
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;

import io.smallrye.jwt.KeyFormat;
import io.smallrye.jwt.auth.UnresolvableKeyException;
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

    // The 'jsonWebKeys' and 'remoteJwkSet' fields represent the JWK key content and are mutually exclusive.
    // 'remoteJwkSet' only deals with the HTTPS URL based JWK sets while 'jsonWebKeys' represents the JWK key(s)
    // loaded from the JWK set or single JWK key from the file system or class path or HTTP URL.
    protected List<JWK> jsonWebKeys;
    // 'remoteJwkSet' represents the JWK set loaded from the HTTPS URL.
    protected RemoteJwkSet remoteJwkSet;

    protected JWTAuthContextInfo authContextInfo;

    public AbstractKeyLocationResolver(JWTAuthContextInfo authContextInfo) throws UnresolvableKeyException {
        this.authContextInfo = authContextInfo;
        PrincipalLogging.log.authContextInfo(authContextInfo);
    }

    protected static boolean isMatchingJwkAvailable(List<JWK> keys, String kid) {
        if (kid != null) {
            for (JWK currentJwk : keys) {
                if (kid.equals(currentJwk.getKeyID())) {
                    return true;
                }
            }
        }
        return false;
    }

    protected static void verifyKid(String actualKid, String expectedKid) throws UnresolvableKeyException {
        if (expectedKid != null) {
            if (actualKid != null && !actualKid.equals(expectedKid)) {
                PrincipalLogging.log.invalidTokenKidHeader(actualKid, expectedKid);
                throw PrincipalMessages.msg.invalidTokenKid();
            }
        }
    }

    protected boolean initializeHttpsJwks(String location) throws IOException {
        if (mayBeFormat(KeyFormat.JWK) && location != null
                && (location.startsWith(HTTPS_SCHEME) || location.startsWith(HTTP_SCHEME))) {
            PrincipalLogging.log.tryCreateKeyFromHttpsJWKS();
            try {
                remoteJwkSet = createRemoteJwkSet(location);
                remoteJwkSet.refresh();
                return true;
            } catch (IOException ex) {
                remoteJwkSet = null;
                return false;
            }
        }
        return false;
    }

    protected RemoteJwkSet createRemoteJwkSet(String location) {
        return new RemoteJwkSet(location, authContextInfo);
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

    protected static JWK getJsonWebKey(String kid, List<JWK> keys, String algo) {
        PrincipalLogging.log.tryCreateKeyFromJWKS();

        try {
            if (kid != null) {
                for (JWK currentJwk : keys) {
                    String jwkAlg = currentJwk.getAlgorithm() != null ? currentJwk.getAlgorithm().getName() : null;
                    if (kid.equals(currentJwk.getKeyID())
                            && (jwkAlg == null || algo.equals(jwkAlg))) {
                        return currentJwk;
                    }
                }
            }
            // if JWK set contains a single JWK only then try to use it
            // but only if 'kid' is not set in both the token and this JWK
            if (keys.size() == 1 && (kid == null || keys.get(0).getKeyID() == null)) {
                String jwkAlg = keys.get(0).getAlgorithm() != null ? keys.get(0).getAlgorithm().getName() : null;
                if (jwkAlg == null || algo.equals(jwkAlg)) {
                    return keys.get(0);
                }
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
            throw PrincipalMessages.msg.failedToLoadKeyFromLocation(keyLocation, e);
        }
    }

    protected static void reportUnresolvableKeyException(String keyContent, String keyLocation)
            throws UnresolvableKeyException {
        if (keyContent != null) {
            throw PrincipalMessages.msg.failedToLoadKeyWhileResolving();
        } else {
            throw PrincipalMessages.msg.failedToLoadKeyFromLocationWhileResolving(keyLocation);
        }
    }

    protected JWK tryAsJwk(String kid, String configuredAlgo) throws UnresolvableKeyException {
        if (remoteJwkSet != null) {
            return getHttpsJwk(kid, configuredAlgo);
        } else if (jsonWebKeys != null) {
            return getJsonWebKey(kid, jsonWebKeys, configuredAlgo);
        } else {
            return null;
        }
    }

    protected JWK getHttpsJwk(String kid, String algo) {
        PrincipalLogging.log.tryCreateKeyFromHttpsJWKS();

        try {
            List<JWK> theKeys = remoteJwkSet.getKeys();
            JWK theKey = getJsonWebKey(kid, theKeys, algo);
            if (theKey != null || isMatchingJwkAvailable(theKeys, kid)) {
                return theKey;
            }
        } catch (Exception e) {
            PrincipalLogging.log.failedToCreateKeyFromJWKSet(e);
        }

        remoteJwkSet.forcedRefresh();

        try {
            PrincipalLogging.log.tryCreateKeyFromJWKSAfterRefresh();
            return getJsonWebKey(kid, remoteJwkSet.getKeys(), algo);
        } catch (Exception e) {
            PrincipalLogging.log.failedToCreateKeyFromJWKSAfterRefresh(e);
        }
        return null;
    }

    protected JWK getJsonWebKey(String kid, String algo) {
        return getJsonWebKey(kid, jsonWebKeys, algo);
    }

    protected JWK tryJWKContent(final String content, String keyId, String algo, boolean encoded) {
        jsonWebKeys = KeyUtils.loadJsonWebKeys(content);
        JWK jwk = null;
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

    protected void loadJWKContent(final String content) {
        jsonWebKeys = KeyUtils.loadJsonWebKeys(content);
    }

    protected JWK loadFromJwk(String content, String keyId, String algo) {
        JWK jwk = null;
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

    protected Key getSecretKeyFromJwk(JWK jwk) {
        if (jwk instanceof OctetSequenceKey) {
            return ((OctetSequenceKey) jwk).toSecretKey("AES");
        }
        return null;
    }

    protected static X509Certificate loadPEMCertificate(String content) {
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
}
