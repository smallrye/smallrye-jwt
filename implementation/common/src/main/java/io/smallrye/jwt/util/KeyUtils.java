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
package io.smallrye.jwt.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;

import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;

import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;

/**
 * Utility methods for dealing with decoding public and private keys resources
 */
public final class KeyUtils {

    private static final String RSA = "RSA";
    private static final String EC = "EC";

    private KeyUtils() {
    }

    public static PrivateKey readPrivateKey(String pemResName) throws IOException, GeneralSecurityException {
        return readPrivateKey(pemResName, SignatureAlgorithm.RS256);
    }

    public static PrivateKey readPrivateKey(String pemResName, SignatureAlgorithm algo)
            throws IOException, GeneralSecurityException {
        InputStream contentIS = ResourceUtils.getAsClasspathResource(pemResName);
        byte[] tmp = new byte[4096];
        int length = contentIS.read(tmp);
        return decodePrivateKey(new String(tmp, 0, length), algo);
    }

    public static PrivateKey readDecryptionPrivateKey(String pemResName) throws IOException, GeneralSecurityException {
        return readDecryptionPrivateKey(pemResName, KeyEncryptionAlgorithm.RSA_OAEP);
    }

    public static PrivateKey readDecryptionPrivateKey(String pemResName, KeyEncryptionAlgorithm algo)
            throws IOException, GeneralSecurityException {
        InputStream contentIS = ResourceUtils.getAsClasspathResource(pemResName);
        byte[] tmp = new byte[4096];
        int length = contentIS.read(tmp);
        return decodeDecryptionPrivateKey(new String(tmp, 0, length), algo);
    }

    public static PublicKey readPublicKey(String pemResName) throws IOException, GeneralSecurityException {
        return readPublicKey(pemResName, SignatureAlgorithm.RS256);
    }

    public static PublicKey readPublicKey(String pemResName, SignatureAlgorithm algo)
            throws IOException, GeneralSecurityException {
        InputStream contentIS = ResourceUtils.getAsClasspathResource(pemResName);
        byte[] tmp = new byte[4096];
        int length = contentIS.read(tmp);
        return decodePublicKey(new String(tmp, 0, length), algo);
    }

    public static PublicKey readEncryptionPublicKey(String pemResName) throws IOException, GeneralSecurityException {
        return readEncryptionPublicKey(pemResName, KeyEncryptionAlgorithm.RSA_OAEP);
    }

    public static PublicKey readEncryptionPublicKey(String pemResName, KeyEncryptionAlgorithm algo)
            throws IOException, GeneralSecurityException {
        InputStream contentIS = ResourceUtils.getAsClasspathResource(pemResName);
        byte[] tmp = new byte[4096];
        int length = contentIS.read(tmp);
        return decodeEncryptionPublicKey(new String(tmp, 0, length), algo);
    }

    public static KeyPair generateKeyPair(int keySize) throws NoSuchAlgorithmException {
        return generateKeyPair(keySize, SignatureAlgorithm.RS256);
    }

    public static KeyPair generateKeyPair(int keySize, SignatureAlgorithm algo) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyFactoryAlgorithm(algo));
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
        return decodePrivateKey(pemEncoded, SignatureAlgorithm.RS256);
    }

    /**
     * Decode a PEM private key
     * 
     * @param pemEncoded - pem string for key
     * @param algo - signature algorithm
     * @return Private key instance
     * @throws GeneralSecurityException - on failure to decode and create key
     */
    public static PrivateKey decodePrivateKey(String pemEncoded, SignatureAlgorithm algo) throws GeneralSecurityException {
        return decodePrivateKeyInternal(pemEncoded, keyFactoryAlgorithm(algo));
    }

    /**
     * Decode a decryption PEM private key
     *
     * @param pemEncoded - pem string for key
     * @return Private key instance
     * @throws GeneralSecurityException - on failure to decode and create key
     */
    public static PrivateKey decodeDecryptionPrivateKey(String pemEncoded) throws GeneralSecurityException {
        return decodePrivateKeyInternal(pemEncoded, "RSA");
    }

    /**
     * Decode a decryption PEM private key
     *
     * @param pemEncoded - pem string for key
     * @param algo - key encryption algorithm
     * @return Private key instance
     * @throws GeneralSecurityException - on failure to decode and create key
     */
    public static PrivateKey decodeDecryptionPrivateKey(String pemEncoded, KeyEncryptionAlgorithm algo)
            throws GeneralSecurityException {
        return decodePrivateKeyInternal(pemEncoded, encryptionKeyFactoryAlgorithm(algo));
    }

    static PrivateKey decodePrivateKeyInternal(String pemEncoded, String algo) throws GeneralSecurityException {
        pemEncoded = removePemKeyBeginEnd(pemEncoded);
        byte[] pkcs8EncodedBytes = Base64.getDecoder().decode(pemEncoded);

        // extract the private key

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
        KeyFactory kf = KeyFactory.getInstance(algo);
        return kf.generatePrivate(keySpec);
    }

    /**
     * Decode a PEM encoded public key string to an RSA PublicKey
     * 
     * @param pemEncoded - PEM string for public key
     * @return PublicKey
     * @throws GeneralSecurityException on decode failure
     */
    public static PublicKey decodePublicKey(String pemEncoded) throws GeneralSecurityException {
        return decodePublicKey(pemEncoded, SignatureAlgorithm.RS256);
    }

    public static SecretKey createSecretKeyFromSecret(String secret) {
        byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
        return new SecretKeySpec(secretBytes, "AES");
    }

    /**
     * Decode a PEM encoded public key string to an RSA or EllipticCurve PublicKey
     * 
     * @param pemEncoded - PEM string for public key
     * @param algo signature algorithm
     * @return PublicKey
     * @throws GeneralSecurityException on decode failure
     */
    public static PublicKey decodePublicKey(String pemEncoded, SignatureAlgorithm algo) throws GeneralSecurityException {
        pemEncoded = removePemKeyBeginEnd(pemEncoded);
        byte[] encodedBytes = Base64.getDecoder().decode(pemEncoded);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(encodedBytes);
        KeyFactory kf = KeyFactory.getInstance(keyFactoryAlgorithm(algo));
        return kf.generatePublic(spec);
    }

    public static PublicKey decodeEncryptionPublicKey(String pemEncoded, KeyEncryptionAlgorithm algo)
            throws GeneralSecurityException {
        pemEncoded = removePemKeyBeginEnd(pemEncoded);
        byte[] encodedBytes = Base64.getDecoder().decode(pemEncoded);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(encodedBytes);
        KeyFactory kf = KeyFactory.getInstance(encryptionKeyFactoryAlgorithm(algo));
        return kf.generatePublic(spec);
    }

    static String keyFactoryAlgorithm(SignatureAlgorithm algo) throws NoSuchAlgorithmException {
        if (algo.name().startsWith("RS")) {
            return RSA;
        }
        if (algo.name().startsWith("ES")) {
            return EC;
        }
        throw JWTUtilMessages.msg.unsupportedAlgorithm(algo.name());
    }

    static String encryptionKeyFactoryAlgorithm(KeyEncryptionAlgorithm algo) throws NoSuchAlgorithmException {
        if (algo.name().startsWith("RS")) {
            return RSA;
        }
        if (algo.name().startsWith("EC")) {
            return EC;
        }
        throw JWTUtilMessages.msg.unsupportedAlgorithm(algo.name());
    }

    /**
     * Decode a PEM encoded certificate string to an RSA PublicKey
     * 
     * @param pemEncoded - PEM string for certificate
     * @return PublicKey
     * @throws GeneralSecurityException on decode failure
     */
    public static PublicKey decodeCertificate(String pemEncoded) throws GeneralSecurityException {
        return getCertificate(pemEncoded).getPublicKey();
    }

    /**
     * Decode a PEM encoded certificate string to X509Certificate
     *
     * @param pemEncoded - PEM string for certificate
     * @return X509Certificate
     * @throws GeneralSecurityException on decode failure
     */
    public static X509Certificate getCertificate(String pemEncoded) throws GeneralSecurityException {
        pemEncoded = removeCertBeginEnd(pemEncoded);
        byte[] encodedBytes = Base64.getDecoder().decode(pemEncoded);
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(encodedBytes));
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

        String content = ResourceUtils.readResource(keyLocation);
        if (content == null) {
            throw JWTUtilMessages.msg.keyNotFound(keyLocation);
        }
        return content;
    }

    static PrivateKey tryAsPEMPrivateKey(String content) {
        JWTUtilLogging.log.creatingKeyFromPemKey();
        try {
            return decodePrivateKey(content);
        } catch (Exception e) {
            JWTUtilLogging.log.creatingKeyFromPemKeyFailed(e);
        }
        return null;
    }

    static PublicKey tryAsPEMPublicKey(String content) {
        JWTUtilLogging.log.creatingKeyFromPemKey();
        try {
            return KeyUtils.decodePublicKey(content);
        } catch (Exception e) {
            JWTUtilLogging.log.creatingKeyFromPemKeyFailed(e);
        }
        return null;
    }

    static PublicKey tryAsPEMCertificate(String content) {
        JWTUtilLogging.log.creatingKeyFromPemCertificate();
        try {
            return KeyUtils.decodeCertificate(content);
        } catch (Exception e) {
            JWTUtilLogging.log.creatingKeyFromPemCertificateFailed(e);
        }
        return null;
    }

    public static List<JsonWebKey> loadJsonWebKeys(String content) {
        JWTUtilLogging.log.loadingJwks();

        JsonObject jwks = null;
        try (JsonReader reader = Json.createReader(new StringReader(content))) {
            jwks = reader.readObject();
        } catch (Exception ex) {
            JWTUtilLogging.log.loadingJwksFailed(ex);
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
            JWTUtilLogging.log.parsingJwksFailed();
            return null;
        }
        return localKeys;
    }

    static JsonWebKey createJsonWebKey(JsonObject jsonObject) throws Exception {
        return JsonWebKey.Factory.newJwk(JsonUtil.parseJson(jsonObject.toString()));
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
