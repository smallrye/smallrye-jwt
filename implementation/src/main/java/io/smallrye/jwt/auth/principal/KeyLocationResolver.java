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

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.URL;
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

import org.jboss.logging.Logger;
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

import io.smallrye.jwt.KeyUtils;

/**
 * This implements the MP-JWT 1.1 mp.jwt.verify.publickey.location config property resolution logic
 */
public class KeyLocationResolver implements VerificationKeyResolver {
    private static final Logger LOGGER = Logger.getLogger(KeyLocationResolver.class);
    private static final String HTTPS_SCHEME = "https:";
    private static final String HTTP_BASED_SCHEME = "http";
    private static final String CLASSPATH_SCHEME = "classpath:";
    private static final String FILE_SCHEME = "file:";

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

    private JWTAuthContextInfo authContextInfo;

    public KeyLocationResolver(JWTAuthContextInfo authContextInfo) throws UnresolvableKeyException {
        this.authContextInfo = authContextInfo;
        try {
            initializeKeyContent();
        } catch (Exception e) {
            throw new UnresolvableKeyException("Failed to load a key from: " + authContextInfo.getPublicKeyLocation(), e);
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
            throw new UnresolvableKeyException("Failed to resolve a key from: " + authContextInfo.getPublicKeyLocation());
        }
        return key;
    }

    private PublicKey tryAsJwk(JsonWebSignature jws) throws UnresolvableKeyException {
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
        LOGGER.debugf("Trying to create a key from the HTTPS JWK(S)...");

        try {
            return getKeyFromJsonWebKeys(kid, httpsJwks.getJsonWebKeys());
        } catch (Exception e) {
            LOGGER.debug("Failed to create a key from the HTTPS JWK(S)", e);
        }
        return null;
    }

    PublicKey getJsonWebKey(String kid) {
        LOGGER.debugf("Trying the create a key from the JWK(S)...");

        try {
            return getKeyFromJsonWebKeys(kid, jsonWebKeys);
        } catch (Exception e) {
            LOGGER.debug("Failed to create a key from the JWK(S)", e);
        }

        return null;
    }

    private static void verifyKid(JsonWebSignature jws, String expectedKid) throws UnresolvableKeyException {
        if (expectedKid != null) {
            String kid = getKid(jws);
            if (kid != null && !kid.equals(expectedKid)) {
                LOGGER.debugf("Invalid token 'kid' header: %s, expected: %s", kid, expectedKid);
                throw new UnresolvableKeyException("Invalid token 'kid' header");
            }
        }
    }

    private static String getKid(JsonWebSignature jws) throws UnresolvableKeyException {
        return jws.getHeaders().getStringHeaderValue(JsonWebKey.KEY_ID_PARAMETER);
    }

    protected void initializeKeyContent() throws Exception {
        if (authContextInfo.getPublicKeyLocation().startsWith(HTTPS_SCHEME)) {
            LOGGER.debugf("Trying to load the keys from the HTTPS JWK(S)...");
            httpsJwks = initializeHttpsJwks();
            httpsJwks.setDefaultCacheDuration(authContextInfo.getJwksRefreshInterval().longValue() * 60L);
            try {
                httpsJwks.refresh();
                return;
            } catch (JoseException ex) {
                // It is likely not a JWK set, continue
            }
        }

        String content = readKeyContent(authContextInfo.getPublicKeyLocation());
        // Try to init the verification key from the local PEM or JWK(S) content
        verificationKey = tryAsPEMPublicKey(content);
        if (verificationKey == null) {
            verificationKey = tryAsPEMCertificate(content);
        }
        if (verificationKey == null) {
            tryJWKContent(content);
        }

        if (verificationKey == null && jsonWebKeys == null) {
            // Try Base64 Decoding
            try {
                content = new String(Base64.getUrlDecoder().decode(content.getBytes(StandardCharsets.UTF_8)),
                        StandardCharsets.UTF_8);
                tryJWKContent(content);
            } catch (IllegalArgumentException e) {
                LOGGER.debug("Unable to decode content using Base64 decoder", e);
            }
        }
    }

    private void tryJWKContent(final String content) {
        jsonWebKeys = loadJsonWebKeys(content);
        if (jsonWebKeys != null && authContextInfo.getTokenKeyId() != null) {
            verificationKey = getJsonWebKey(authContextInfo.getTokenKeyId());
        }
    }

    protected HttpsJwks initializeHttpsJwks() {
        return new HttpsJwks(authContextInfo.getPublicKeyLocation());
    }

    protected String readKeyContent(String keyLocation) throws IOException {

        InputStream is = null;

        if (keyLocation.startsWith(HTTP_BASED_SCHEME)) {
            // It can be PEM key at HTTP or HTTPS URL, JWK set at HTTP URL or single JWK at either HTTP or HTTPS URL
            is = getUrlResolver().resolve(keyLocation);
        } else if (keyLocation.startsWith(FILE_SCHEME)) {
            is = getAsFileSystemResource(keyLocation.substring(FILE_SCHEME.length()));
        } else if (keyLocation.startsWith(CLASSPATH_SCHEME)) {
            is = getAsClasspathResource(keyLocation.substring(CLASSPATH_SCHEME.length()));
        } else {
            is = getAsFileSystemResource(keyLocation);
            if (is == null) {
                is = getAsClasspathResource(keyLocation);
            }
            if (is == null) {
                is = getUrlResolver().resolve(keyLocation);
            }
        }

        if (is == null) {
            throw new IOException("No resource with the named " + keyLocation + " location exists");
        }

        StringWriter contents = new StringWriter();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
            String line = null;
            while ((line = reader.readLine()) != null) {
                contents.write(line);
            }
        }
        return contents.toString();
    }

    protected UrlStreamResolver getUrlResolver() {
        return new UrlStreamResolver();
    }

    static PublicKey tryAsPEMPublicKey(String content) {
        LOGGER.debugf("Trying to create a key from the encoded PEM key...");
        try {
            return KeyUtils.decodePublicKey(content);
        } catch (Exception e) {
            LOGGER.debug("Failed to create a key from the encoded PEM key", e);
        }
        return null;
    }

    static PublicKey tryAsPEMCertificate(String content) {
        LOGGER.debugf("Trying to create a key from the encoded PEM certificate...");
        try {
            return KeyUtils.decodeCertificate(content);
        } catch (Exception e) {
            LOGGER.debug("Failed to to create a key from the encoded PEM certificate", e);
        }
        return null;
    }

    static List<JsonWebKey> loadJsonWebKeys(String content) {
        LOGGER.debugf("Trying to load the local JWK(S)...");

        JsonObject jwks = null;
        try (JsonReader reader = Json.createReader(new StringReader(content))) {
            jwks = reader.readObject();
        } catch (Exception ex) {
            LOGGER.debug("Failed to load the JWK(S)");
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
            LOGGER.debug("Failed to parse the JWK JSON representation");
            return null;
        }
        return localKeys;
    }

    static PublicKey getKeyFromJsonWebKeys(String kid, List<JsonWebKey> keys) {
        if (kid != null) {
            for (JsonWebKey currentJwk : keys) {
                if (kid.equals(currentJwk.getKeyId())) {
                    return PublicJsonWebKey.class.cast(currentJwk).getPublicKey();
                }
            }
        }
        // if JWK set contains a single JWK only then try to use it
        // but only if 'kid' is not set in both the token and this JWK
        if (keys.size() == 1 && (kid == null || keys.get(0).getKeyId() == null)) {
            return PublicJsonWebKey.class.cast(keys.get(0)).getPublicKey();
        }
        return null;
    }

    static JsonWebKey createJsonWebKey(JsonObject jsonObject) throws Exception {
        return JsonWebKey.Factory.newJwk(JsonUtil.parseJson(jsonObject.toString()));
    }

    static InputStream getAsFileSystemResource(String publicKeyLocation) throws IOException {
        try {
            return new FileInputStream(publicKeyLocation);
        } catch (FileNotFoundException e) {
            return null;
        }
    }

    static InputStream getAsClasspathResource(String location) {
        return Thread.currentThread().getContextClassLoader().getResourceAsStream(location);
    }

    static class UrlStreamResolver {
        public InputStream resolve(String keyLocation) throws IOException {
            return new URL(keyLocation).openStream();
        }
    }
}
