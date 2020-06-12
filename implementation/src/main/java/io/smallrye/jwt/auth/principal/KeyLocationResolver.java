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
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;

import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.UnresolvableKeyException;

import io.smallrye.jwt.KeyFormat;
import io.smallrye.jwt.KeyUtils;
import io.smallrye.jwt.ResourceUtils;
import io.smallrye.jwt.ResourceUtils.UrlStreamResolver;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;

/**
 * This implements the MP-JWT 1.1 mp.jwt.verify.publickey.location config property resolution logic
 */
public class KeyLocationResolver implements VerificationKeyResolver {
    private static final String HTTPS_SCHEME = "https:";

    // The verification key can be calculated only once and used for all the token verification requests.
    // It will be created in the constructor if the PEM or the local JWK(S) content is available.
    // 'smallrye.jwt.token.kid' has to be set for the verificationKey to be created from the local JWK(S).
    PublicKey verificationKey;

    // The 'jsonWebKeys' and 'httpsJwks' fields represent the JWK key content and are mutually exclusive.
    // 'httpsJwks' only deals with the HTTPS URL based JWK sets while 'jsonWebKeys' represents the JWK key(s)
    // loaded from the JWK set or single JWK key from the file system or class path or HTTP URL.
    private List<JsonWebKey> jsonWebKeys;
    // 'httpsJwks' represents the JWK set loaded from the HTTPS URL.
    private HttpsJwks httpsJwks;
    private long lastForcedRefreshTime;
    private Object forcedRefreshLock = new Object();

    private JWTAuthContextInfo authContextInfo;

    public KeyLocationResolver(JWTAuthContextInfo authContextInfo) throws UnresolvableKeyException {
        this.authContextInfo = authContextInfo;
        PrincipalLogging.log.authContextInfo(authContextInfo);

        try {
            initializeKeyContent();
        } catch (Exception e) {
            if (authContextInfo.getPublicKeyContent() != null) {
                throw PrincipalMessages.msg.failedToLoadPublicKey(e);
            } else {
                throw PrincipalMessages.msg.failedToLoadPublicKeyFromLocation(authContextInfo.getPublicKeyLocation(), e);
            }
        }
    }

    @Override
    public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext) throws UnresolvableKeyException {
        verifyKid(jws, authContextInfo.getTokenKeyId());

        // The verificationKey may have been calculated in the constructor from the local PEM, or,
        // if authContextInfo.getTokenKeyId() is not null - from the local JWK(S) content.
        if (verificationKey != null) {
            return verificationKey;
        }

        // At this point the key can be loaded from either the HTTPS or local JWK(s) content using
        // the current token kid to select the key.
        PublicKey key = tryAsJwk(jws);

        if (key == null) {
            if (authContextInfo.getPublicKeyContent() != null) {
                throw PrincipalMessages.msg.failedToLoadPublicKeyWhileResolving();
            } else {
                throw PrincipalMessages.msg
                        .failedToLoadPublicKeyFromLocationWhileResolving(authContextInfo.getPublicKeyLocation());
            }
        }
        return key;
    }

    private PublicKey tryAsJwk(JsonWebSignature jws) {
        String kid = getKid(jws);

        if (httpsJwks != null) {
            return getHttpsJwk(kid);
        } else if (jsonWebKeys != null) {
            return getJsonWebKey(kid);
        } else {
            return null;
        }
    }

    PublicKey getHttpsJwk(String kid) {
        try {
            List<JsonWebKey> theKeys = httpsJwks.getJsonWebKeys();
            PublicKey theKey = getKeyFromJsonWebKeys(kid, theKeys, authContextInfo.getSignatureAlgorithm());
            if (theKey != null || isMatchingJwkAvailable(theKeys, kid)) {
                return theKey;
            }
        } catch (Exception e) {
            PrincipalLogging.log.failedToCreateKeyFromJWKSet(e);
            return null;
        }

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
                    return null;
                }
            } else {
                PrincipalLogging.log.matchingKidIsNotAvailableButJWTSRefreshed(authContextInfo.getForcedJwksRefreshInterval());
            }
        }

        try {
            PrincipalLogging.log.tryCreateKeyFromJWKSAfterRefresh();
            return getKeyFromJsonWebKeys(kid, httpsJwks.getJsonWebKeys(), authContextInfo.getSignatureAlgorithm());
        } catch (Exception e) {
            PrincipalLogging.log.failedToCreateKeyFromJWKSAfterRefresh(e);
        }
        return null;
    }

    private static boolean isMatchingJwkAvailable(List<JsonWebKey> keys, String kid) {
        if (kid != null) {
            for (JsonWebKey currentJwk : keys) {
                if (kid.equals(currentJwk.getKeyId())) {
                    return true;
                }
            }
        }
        return false;
    }

    PublicKey getJsonWebKey(String kid) {
        PrincipalLogging.log.tryCreateKeyFromJWKS();

        try {
            return getKeyFromJsonWebKeys(kid, jsonWebKeys, authContextInfo.getSignatureAlgorithm());
        } catch (Exception e) {
            PrincipalLogging.log.failedToCreateKeyFromJWKS(e);
        }

        return null;
    }

    private static void verifyKid(JsonWebSignature jws, String expectedKid) throws UnresolvableKeyException {
        if (expectedKid != null) {
            String kid = getKid(jws);
            if (kid != null && !kid.equals(expectedKid)) {
                PrincipalLogging.log.invalidTokenKidHeader(kid, expectedKid);
                throw PrincipalMessages.msg.invalidTokenKid();
            }
        }
    }

    private static String getKid(JsonWebSignature jws) {
        return jws.getHeaders().getStringHeaderValue(JsonWebKey.KEY_ID_PARAMETER);
    }

    protected void initializeKeyContent() throws Exception {

        if (mayBeFormat(KeyFormat.JWK) && authContextInfo.getPublicKeyLocation() != null
                && authContextInfo.getPublicKeyLocation().startsWith(HTTPS_SCHEME)) {
            PrincipalLogging.log.tryLoadKeyFromJWKS();
            httpsJwks = initializeHttpsJwks();
            httpsJwks.setDefaultCacheDuration(authContextInfo.getJwksRefreshInterval().longValue() * 60L);
            try {
                httpsJwks.refresh();
                return;
            } catch (JoseException ex) {
                // It is likely not a JWK set, continue
            }
        }

        String content = authContextInfo.getPublicKeyContent() != null
                ? authContextInfo.getPublicKeyContent()
                : readKeyContent(authContextInfo.getPublicKeyLocation());

        // Try to init the verification key from the local PEM or JWK(S) content
        if (mayBeFormat(KeyFormat.PEM_KEY)) {
            verificationKey = tryAsPEMPublicKey(content, authContextInfo.getSignatureAlgorithm());
            if (verificationKey != null || isFormat(KeyFormat.PEM_KEY)) {
                return;
            }
        }
        if (mayBeFormat(KeyFormat.PEM_CERTIFICATE)) {
            verificationKey = tryAsPEMCertificate(content);
            if (verificationKey != null || isFormat(KeyFormat.PEM_CERTIFICATE)) {
                return;
            }
        }
        if (mayBeFormat(KeyFormat.JWK)) {
            PrincipalLogging.log.checkKeyContentIsJWKKeyOrJWKKeySet();
            tryJWKContent(content, false);
            if (verificationKey != null || isFormat(KeyFormat.JWK)) {
                return;
            }
        }
        if (jsonWebKeys == null && mayBeFormat(KeyFormat.JWK_BASE64URL)) {
            // Try Base64 Decoding
            try {
                PrincipalLogging.log.checkKeyContentIsBase64EncodedJWKKeyOrJWKKeySet();
                content = new String(Base64.getUrlDecoder().decode(content.getBytes(StandardCharsets.UTF_8)),
                        StandardCharsets.UTF_8);
                tryJWKContent(content, true);
            } catch (IllegalArgumentException e) {
                PrincipalLogging.log.unableToDecodeContentUsingBase64(e);
            }
        }
    }

    private void tryJWKContent(final String content, boolean encoded) {
        jsonWebKeys = loadJsonWebKeys(content);
        if (jsonWebKeys != null && authContextInfo.getTokenKeyId() != null) {
            verificationKey = getJsonWebKey(authContextInfo.getTokenKeyId());
            if (verificationKey != null) {
                if (encoded) {
                    PrincipalLogging.log.publicKeyCreatedFromEncodedJWKKeyOrJWKKeySet();
                } else {
                    PrincipalLogging.log.publicKeyCreatedFromJWKKeyOrJWKKeySet();
                }
            }
        }
    }

    protected HttpsJwks initializeHttpsJwks() {
        return new HttpsJwks(authContextInfo.getPublicKeyLocation());
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

    static PublicKey tryAsPEMPublicKey(String content, SignatureAlgorithm algo) {
        PrincipalLogging.log.checkKeyContentIsBase64EncodedPEMKey();
        PublicKey key = null;
        try {
            key = KeyUtils.decodePublicKey(content, algo);
            PrincipalLogging.log.publicKeyCreatedFromEncodedPEMKey();
        } catch (Exception e) {
            PrincipalLogging.log.keyContentIsNotValidEncodedPEMKey(e);
        }
        return key;
    }

    static PublicKey tryAsPEMCertificate(String content) {
        PrincipalLogging.log.checkKeyContentIsBase64EncodedPEMCertificate();
        PublicKey key = null;
        try {
            key = KeyUtils.decodeCertificate(content);
            PrincipalLogging.log.publicKeyCreatedFromEncodedPEMCertificate();
        } catch (Exception e) {
            PrincipalLogging.log.keyContentIsNotValidEncodedPEMCertificate(e);
        }
        return key;
    }

    static List<JsonWebKey> loadJsonWebKeys(String content) {
        PrincipalLogging.log.tryLoadLocalJWKS();

        JsonObject jwks = null;
        try (JsonReader reader = Json.createReader(new StringReader(content))) {
            jwks = reader.readObject();
        } catch (Exception ex) {
            PrincipalLogging.log.failedToLoadJWKS();
            return null;
        }

        List<JsonWebKey> localKeys = null;
        JsonArray keys = jwks.getJsonArray(JsonWebKeySet.JWK_SET_MEMBER_NAME);

        try {
            if (keys != null) {
                // JWK set
                localKeys = new ArrayList<>(keys.size());
                for (int i = 0; i < keys.size(); i++) {
                    localKeys.add(createJsonWebKey(keys.getJsonObject(i)));
                }
            } else {
                // single JWK
                localKeys = Collections.singletonList(createJsonWebKey(jwks));
            }
        } catch (Exception ex) {
            PrincipalLogging.log.failedToParseJWKJsonRepresentation();
            return null;
        }
        return localKeys;
    }

    static PublicKey getKeyFromJsonWebKeys(String kid, List<JsonWebKey> keys, SignatureAlgorithm algo) {
        if (kid != null) {
            for (JsonWebKey currentJwk : keys) {
                if (kid.equals(currentJwk.getKeyId())
                        && (currentJwk.getAlgorithm() == null || algo.getAlgorithm().equals(currentJwk.getAlgorithm()))) {
                    return PublicJsonWebKey.class.cast(currentJwk).getPublicKey();
                }
            }
        }
        // if JWK set contains a single JWK only then try to use it
        // but only if 'kid' is not set in both the token and this JWK
        if (keys.size() == 1 && (kid == null || keys.get(0).getKeyId() == null)
                && (keys.get(0).getAlgorithm() == null || algo.getAlgorithm().equals(keys.get(0).getAlgorithm()))) {
            return PublicJsonWebKey.class.cast(keys.get(0)).getPublicKey();
        }
        return null;
    }

    static JsonWebKey createJsonWebKey(JsonObject jsonObject) throws Exception {
        return JsonWebKey.Factory.newJwk(JsonUtil.parseJson(jsonObject.toString()));
    }

    boolean mayBeFormat(KeyFormat format) {
        return isFormat(format) || authContextInfo.getKeyFormat() == KeyFormat.ANY;
    }

    boolean isFormat(KeyFormat format) {
        return authContextInfo.getKeyFormat() == format;
    }
}
