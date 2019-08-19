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
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.URI;
import java.net.URL;
import java.security.Key;
import java.security.PublicKey;
import java.util.List;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;

import org.jboss.logging.Logger;
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

    // The 'content' and 'httpsJwks' fields are used to keep the key content and mutually exclusive.
    // 'content' represents the key(s) loaded from all resources but the HTTPS URL based JWK set.
    private String content;
    // 'httpsJwks' represents the JWK set loaded from the HTTPS URL.
    private HttpsJwks httpsJwks;

    // If the 'smallrye.jwt.token.kid' is set then the verification key will be calculated
    // only once and used for all the token verification requests
    volatile PublicKey verificationKey;

    private JWTAuthContextInfo authContextInfo;

    public KeyLocationResolver(JWTAuthContextInfo authContextInfo) throws UnresolvableKeyException {
        this.authContextInfo = authContextInfo;
        try {
            loadContents();
        } catch (Exception e) {
            throw new UnresolvableKeyException("Failed to load a key from: " + authContextInfo.getPublicKeyLocation(), e);
        }
    }

    @Override
    public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext) throws UnresolvableKeyException {
        if (verificationKey != null) {
            return verificationKey;
        }
        PublicKey key = tryAsJWK(jws);
        if (key == null) {
            key = tryAsPEM();
        }
        if (key == null) {
            throw new UnresolvableKeyException("Failed to read location as any of JWK, JWKS, PEM. "
                    + authContextInfo.getPublicKeyLocation());
        }
        return key;
    }

    private PublicKey tryAsPEM() {
        try {
            verificationKey = KeyUtils.decodePublicKey(content);
        } catch (Exception e) {
            LOGGER.debug("Failed to read location as PEM", e);
        }
        return verificationKey;
    }

    private String getKid(JsonWebSignature jws) throws UnresolvableKeyException {
        String kid = jws.getHeaders().getStringHeaderValue(JsonWebKey.KEY_ID_PARAMETER);
        if (kid != null) {
            if (authContextInfo.getTokenKeyId() != null && !kid.equals(authContextInfo.getTokenKeyId())) {
                LOGGER.debugf("Invalid token 'kid' header: %s, expected: %s", kid, authContextInfo.getTokenKeyId());
                throw new UnresolvableKeyException("Invalid token 'kid' header");
            }
        } else {
            kid = authContextInfo.getTokenKeyId();
        }
        return kid;
    }

    private PublicKey tryAsJWK(JsonWebSignature jws) throws UnresolvableKeyException {
        String kid = getKid(jws);

        PublicKey publicKey = null;

        try {
            LOGGER.debugf("Trying location as JWK(S)...");

            if (httpsJwks != null) {
                publicKey = getHttpJwk(httpsJwks, kid);
            } else {
                publicKey = getContentJwk(content, kid);
            }
        } catch (Exception e) {
            LOGGER.debug("Failed to read location as JWK(S)", e);
        }

        if (httpsJwks == null && publicKey != null && authContextInfo.getTokenKeyId() != null) {
            // httpsJwks may refresh itself even if the jwksRefreshInterval is set to 0 as it checks HTTPS Cache-Control header
            // so the public key will have to be created per request to ensure the rotation (if any) is effective.
            verificationKey = publicKey;
        }

        return publicKey;
    }

    PublicKey getHttpJwk(HttpsJwks httpsJwks, String kid) throws JoseException, IOException {
        List<JsonWebKey> keys = httpsJwks.getJsonWebKeys();
        if (kid != null) {
            for (JsonWebKey currentJwk : keys) {
                if (kid.equals(currentJwk.getKeyId())) {
                    return PublicJsonWebKey.class.cast(currentJwk).getPublicKey();
                }
            }
        } else if (keys.size() == 1) {
            return PublicJsonWebKey.class.cast(keys.get(0)).getPublicKey();
        }

        return null;
    }

    PublicKey getContentJwk(String content, String kid) throws JoseException {
        JsonObject jwk = null;

        JsonObject jwks;
        try (JsonReader reader = Json.createReader(new StringReader(content))) {
            jwks = reader.readObject();
        }
        JsonArray keys = jwks.getJsonArray(JsonWebKeySet.JWK_SET_MEMBER_NAME);

        if (keys != null) {
            if (kid != null) {
                for (int i = 0; i < keys.size(); i++) {
                    JsonObject currentJwk = keys.getJsonObject(i);
                    if (kid.equals(currentJwk.getString(JsonWebKey.KEY_ID_PARAMETER, null))) {
                        jwk = currentJwk;
                        break;
                    }
                }
            } else if (keys.size() == 1) {
                jwk = keys.getJsonObject(0);
            }
        } else if (kid == null || kid.equals(jwks.getString(JsonWebKey.KEY_ID_PARAMETER, null))) {
            jwk = jwks;
        }

        if (jwk != null) {
            return PublicJsonWebKey.Factory.newPublicJwk(jwk.toString()).getPublicKey();
        }

        return null;
    }

    private void loadContents() throws IOException {
        final URI location = URI.create(authContextInfo.getPublicKeyLocation());

        if ("https".equals(location.getScheme())) {
            httpsJwks = new HttpsJwks(authContextInfo.getPublicKeyLocation());
            httpsJwks.setDefaultCacheDuration(authContextInfo.getJwksRefreshInterval().longValue() * 60L);
            return;
        }

        InputStream is = null;

        if (location.getScheme() != null) {
            if ("classpath".equals(location.getScheme())) {
                is = getAsClasspathResource(location.getSchemeSpecificPart());
            } else if ("file".equals(location.getScheme())) {
                is = getAsFileSystemResource(location.getRawSchemeSpecificPart());
            } else {
                is = new URL(authContextInfo.getPublicKeyLocation()).openStream();
            }
        } else {
            is = getAsClasspathResource(authContextInfo.getPublicKeyLocation());
            if (is == null) {
                is = getAsFileSystemResource(authContextInfo.getPublicKeyLocation());
            }
        }

        if (is == null) {
            throw new IOException("No resource with the named " + location + " location exists");
        }

        StringWriter contents = new StringWriter();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
            String line = reader.readLine();
            while (line != null) {
                if (!line.startsWith("-----BEGIN") && !line.startsWith("-----END")) {
                    // Skip any pem file header/footer
                    contents.write(line);
                }
                line = reader.readLine();
            }
        }
        content = contents.toString();
    }

    private static InputStream getAsFileSystemResource(String publicKeyLocation) throws IOException {
        File f = new File(publicKeyLocation);
        return f.exists() ? new FileInputStream(f) : null;
    }

    private static InputStream getAsClasspathResource(String location) {
        return Thread.currentThread().getContextClassLoader().getResourceAsStream(location);
    }
}
