/*
 *
 *   Copyright 2018 Red Hat, Inc, and individual contributors.
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
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PublicKey;
import java.util.Base64;
import java.util.List;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;

import org.jboss.logging.Logger;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.jose4j.lang.UnresolvableKeyException;

import io.smallrye.jwt.KeyUtils;

/**
 * This implements the MP-JWT 1.1 mp.jwt.verify.publickey.location config property resolution logic
 */
public class KeyLocationResolver implements VerificationKeyResolver {
    private static final Logger log = Logger.getLogger(KeyLocationResolver.class);
    private String location;
    private String json;

    public KeyLocationResolver(String location) {
        this.location = location;
    }
    @Override
    public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext) throws UnresolvableKeyException {
        try {
            loadContents();
        } catch (IOException e) {
            throw new UnresolvableKeyException("Failed to load a key from: " + location, e);
        }
        String kid = jws.getHeaders().getStringHeaderValue("kid");
        
        PublicKey key = tryAsJWK(kid);
        if (key == null) {
            key = tryAsPEM();
        }
        if (key == null) {
            throw new UnresolvableKeyException("Failed to read location as any of JWK, JWKS, PEM; " + location);
        }
        return key;
    }

    private PublicKey tryAsPEM() {
        PublicKey publicKey = null;
        try {
            publicKey = KeyUtils.decodePublicKey(json);
        } catch (Exception e) {
            log.debug("Failed to read location as PEM", e);
        }
        return publicKey;
    }

    private PublicKey tryAsJWK(String kid) {
        PublicKey publicKey = null;
        try {
            log.debugf("Trying location as JWK(S)...");
            
            JsonObject jwk = null;
            
            JsonObject jwks = Json.createReader(new StringReader(json)).readObject();
            JsonArray keys = jwks.getJsonArray("keys");
            if (keys != null) {
                if (kid != null) {
                    for (int i = 0; i < keys.size(); i++) {
                        JsonObject currentJwk = keys.getJsonObject(i);
                        if (kid.equals(currentJwk.getString("kid", null))) {
                            jwk = currentJwk;
                            break;
                        }
                    }
                } else if (keys.size() == 1) {
                    jwk = keys.getJsonObject(0);
                }
            } else if (kid == null || kid.equals(jwks.getString("kid", null))) {
                jwk = jwks;
            }
            if (jwk != null) {
                publicKey = PublicJsonWebKey.Factory.newPublicJwk(jwk.toString()).getPublicKey();
            }
        } catch (Exception e) {
            log.debug("Failed to read location as JWK(S)", e);
        }

        return publicKey;
    }

    private void loadContents() throws IOException {
        StringWriter contents = new StringWriter();
        InputStream is;
        if (location.startsWith("classpath:") || location.indexOf(':') < 0) {
            String path;
            if (location.startsWith("classpath:")) {
                path = location.substring(10);
            } else {
                path = location;
            }
            ClassLoader loader = Thread.currentThread().getContextClassLoader();
            is = loader.getResourceAsStream(path);
        } else {
            URL locationURL = new URL(location);
            is = locationURL.openStream();
        }
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
        json = contents.toString();
        try {
            // Determine if this is base64
            json = new String(Base64.getDecoder().decode(json), StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.debug("contents does not appear to be base64 encoded");
        }
    }
}
