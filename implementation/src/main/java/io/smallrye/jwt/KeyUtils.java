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
package io.smallrye.jwt;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
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
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;

import io.smallrye.jwt.auth.principal.KeyLocationResolver;

/**
 * Utility methods for dealing with decoding public and private keys resources
 */
public final class KeyUtils {

    private static final Logger LOGGER = Logger.getLogger(KeyLocationResolver.class);
    private static final String HTTP_BASED_SCHEME = "http";
    private static final String CLASSPATH_SCHEME = "classpath:";
    private static final String FILE_SCHEME = "file:";
    private static final String RSA = "RSA";

    private KeyUtils() {
    }

    public static PrivateKey readPrivateKey(String pemResName) throws IOException, GeneralSecurityException {
        InputStream contentIS = KeyUtils.class.getResourceAsStream(pemResName);
        byte[] tmp = new byte[4096];
        int length = contentIS.read(tmp);
        return decodePrivateKey(new String(tmp, 0, length));
    }

    public static PublicKey readPublicKey(String pemResName) throws IOException, GeneralSecurityException {
        InputStream contentIS = KeyUtils.class.getResourceAsStream(pemResName);
        byte[] tmp = new byte[4096];
        int length = contentIS.read(tmp);
        return decodePublicKey(new String(tmp, 0, length));
    }

    public static KeyPair generateKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.genKeyPair();
    }

    /**
     * Decode a PEM RSA private key
     * 
     * @param pemEncoded - pem string for key
     * @return RSA private key instance
     * @throws GeneralSecurityException - on failure to decode and create key
     */
    public static PrivateKey decodePrivateKey(String pemEncoded) throws GeneralSecurityException {
        pemEncoded = removePemKeyBeginEnd(pemEncoded);
        byte[] pkcs8EncodedBytes = Base64.getDecoder().decode(pemEncoded);

        // extract the private key

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
        KeyFactory kf = KeyFactory.getInstance(RSA);
        return kf.generatePrivate(keySpec);
    }

    /**
     * Decode a JWK(S) encoded public key string to an RSA PublicKey. This assumes a single JWK in the set as
     * only the first JWK is used.
     * 
     * @param jwksValue - JWKS string value
     * @return PublicKey from RSAPublicKeySpec
     * @throws GeneralSecurityException when RSA security is not supported or public key cannot be decoded
     */
    public static PublicKey decodeJWKSPublicKey(String jwksValue) throws GeneralSecurityException {
        JsonObject jwks;

        try (Reader reader = new StringReader(jwksValue);
                JsonReader json = Json.createReader(reader)) {
            jwks = json.readObject();
        } catch (Exception e) {
            // See if this is base64 encoded
            byte[] decoded = Base64.getDecoder().decode(jwksValue);

            try (InputStream stream = new ByteArrayInputStream(decoded);
                    JsonReader json = Json.createReader(stream)) {
                jwks = json.readObject();
            } catch (IOException ioe) {
                throw new UncheckedIOException(ioe);
            }
        }
        JsonArray keys = jwks.getJsonArray("keys");
        JsonObject jwk;
        if (keys != null) {
            jwk = keys.getJsonObject(0);
        } else {
            // A JWK
            jwk = jwks;
        }
        String e = jwk.getString("e");
        String n = jwk.getString("n");

        byte[] ebytes = Base64.getUrlDecoder().decode(e);
        BigInteger publicExponent = new BigInteger(1, ebytes);
        byte[] nbytes = Base64.getUrlDecoder().decode(n);
        BigInteger modulus = new BigInteger(1, nbytes);
        KeyFactory kf = KeyFactory.getInstance(RSA);
        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
        return kf.generatePublic(rsaPublicKeySpec);
    }

    /**
     * Decode a PEM encoded public key string to an RSA PublicKey
     * 
     * @param pemEncoded - PEM string for public key
     * @return PublicKey
     * @throws GeneralSecurityException on decode failure
     */
    public static PublicKey decodePublicKey(String pemEncoded) throws GeneralSecurityException {
        pemEncoded = removePemKeyBeginEnd(pemEncoded);
        byte[] encodedBytes = Base64.getDecoder().decode(pemEncoded);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(encodedBytes);
        KeyFactory kf = KeyFactory.getInstance(RSA);
        return kf.generatePublic(spec);
    }

    /**
     * Decode a PEM encoded certificate string to an RSA PublicKey
     * 
     * @param pemEncoded - PEM string for certificate
     * @return PublicKey
     * @throws GeneralSecurityException on decode failure
     */
    public static PublicKey decodeCertificate(String pemEncoded) throws GeneralSecurityException {
        pemEncoded = removeCertBeginEnd(pemEncoded);
        byte[] encodedBytes = Base64.getDecoder().decode(pemEncoded);
        return CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(encodedBytes)).getPublicKey();
    }

    /**
     * Strip any -----BEGIN*KEY... header and -----END*KEY... footer and newlines
     * 
     * @param pem encoded string with option header/footer
     * @return a single base64 encoded pem string
     */
    public static String removePemKeyBeginEnd(String pem) {
        pem = pem.replaceAll("-----BEGIN(.*?)KEY-----", "");
        pem = pem.replaceAll("-----END(.*?)KEY-----", "");
        pem = pem.replaceAll("\r\n", "");
        pem = pem.replaceAll("\n", "");
        pem = pem.replaceAll("\\\\n", "");
        return pem.trim();
    }

    /**
     * Strip any -----BEGIN*CERTIFICATE... header and -----END*CERTIFICATE... footer and newlines
     * 
     * @param pem encoded string with option header/footer
     * @return a single base64 encoded pem string
     */
    private static String removeCertBeginEnd(String pem) {
        pem = pem.replaceAll("-----BEGIN(.*?)CERTIFICATE-----", "");
        pem = pem.replaceAll("-----END(.*?)CERTIFICATE-----", "");
        pem = pem.replaceAll("\r\n", "");
        pem = pem.replaceAll("\n", "");
        pem = pem.replaceAll("\\\\n", "");
        return pem.trim();
    }

    static String readKeyContent(String keyLocation) throws IOException {

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

    static UrlStreamResolver getUrlResolver() {
        return new UrlStreamResolver();
    }

    static PrivateKey tryAsPEMPrivateKey(String content) {
        LOGGER.debugf("Trying to create a key from the encoded PEM key...");
        try {
            return decodePrivateKey(content);
        } catch (Exception e) {
            LOGGER.debug("Failed to create a key from the encoded PEM key", e);
        }
        return null;
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
        InputStream is = KeyUtils.class.getResourceAsStream(location);
        if (is == null) {
            is = Thread.currentThread().getContextClassLoader().getResourceAsStream(location);
        }
        return is;
    }

    static class UrlStreamResolver {
        public InputStream resolve(String keyLocation) throws IOException {
            return new URL(keyLocation).openStream();
        }
    }

    public static Key readEncryptionKey(String location, String kid) throws IOException {
        String content = readKeyContent(location);

        Key key = tryAsPEMPublicKey(content);
        if (key == null) {
            key = tryAsPEMCertificate(content);
        }
        if (key == null) {
            List<JsonWebKey> jwks = loadJsonWebKeys(content);
            if (jwks != null) {
                key = getEncryptionKeyFromJwkSet(kid, jwks);
            }
        }
        return key;
    }

    static Key getEncryptionKeyFromJwkSet(String kid, List<JsonWebKey> keys) {
        if (kid != null) {
            for (JsonWebKey currentJwk : keys) {
                if (kid.equals(currentJwk.getKeyId())) {
                    return getPublicOrSecretEncryptingKey(currentJwk);
                }
            }
        }
        // if JWK set contains a single JWK only then try to use it
        // but only if 'kid' is not set in both the token and this JWK
        if (keys.size() == 1 && (kid == null || keys.get(0).getKeyId() == null)) {
            return getPublicOrSecretEncryptingKey(keys.get(0));
        }
        return null;
    }

    static Key getPublicOrSecretEncryptingKey(JsonWebKey currentJwk) {
        List<String> keyOps = currentJwk.getKeyOps();
        if (keyOps == null || keyOps.contains("encryption")) {
            if ("oct".equals(currentJwk.getKeyType())) {
                return OctetSequenceJsonWebKey.class.cast(currentJwk).getKey();
            } else {
                return PublicJsonWebKey.class.cast(currentJwk).getPublicKey();
            }
        }
        return null;
    }

    public static Key readSigningKey(String location, String kid) throws IOException {
        String content = readKeyContent(location);

        Key key = tryAsPEMPrivateKey(content);
        if (key == null) {
            List<JsonWebKey> jwks = loadJsonWebKeys(content);
            if (jwks != null) {
                key = getSigningKeyFromJwkSet(kid, jwks);
            }
        }
        return key;
    }

    static Key getSigningKeyFromJwkSet(String kid, List<JsonWebKey> keys) {
        if (kid != null) {
            for (JsonWebKey currentJwk : keys) {
                if (kid.equals(currentJwk.getKeyId())) {
                    return getPrivateOrSecretSigningKey(currentJwk);
                }
            }
        }
        // if JWK set contains a single JWK only then try to use it
        // but only if 'kid' is not set in both the token and this JWK
        if (keys.size() == 1 && (kid == null || keys.get(0).getKeyId() == null)) {
            return getPrivateOrSecretSigningKey(keys.get(0));
        }
        return null;
    }

    static Key getPrivateOrSecretSigningKey(JsonWebKey currentJwk) {
        List<String> keyOps = currentJwk.getKeyOps();
        if (keyOps == null || keyOps.contains("sign")) {
            if ("oct".equals(currentJwk.getKeyType())) {
                return OctetSequenceJsonWebKey.class.cast(currentJwk).getKey();
            } else {
                return PublicJsonWebKey.class.cast(currentJwk).getPrivateKey();
            }
        }
        return null;
    }
}
