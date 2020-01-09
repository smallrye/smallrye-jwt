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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;

import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.lang.JoseException;

/**
 * Utility methods for dealing with decoding public and private keys resources
 */
public class KeyUtils {
    private static final String RSA = "RSA";

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
        pemEncoded = removeKeyBeginEnd(pemEncoded);
        byte[] pkcs8EncodedBytes = Base64.getDecoder().decode(pemEncoded);

        // extract the private key

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
        KeyFactory kf = KeyFactory.getInstance(RSA);
        return kf.generatePrivate(keySpec);
    }

    /**
     * Decode a JWK(S) encoded public key string to a list of JsonWebKeys.
     *
     * @param jwksValue
     * @return a list of decoded JsonWebKey instances.
     * @throws GeneralSecurityException when the JsonWebKey can not be decoded.
     */
    public static List<JsonWebKey> decodeJsonWebKeySet(String jwksValue) throws GeneralSecurityException {
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
            return Collections.singletonList(createJsonWebKey(jwks));
        }

        List<JsonWebKey> jsonWebKeys = new ArrayList<>(keys.size());
        for (int i = 0; i < keys.size(); i++) {
            jsonWebKeys.add(createJsonWebKey(keys.getJsonObject(i)));
        }

        return jsonWebKeys;
    }

    private static JsonWebKey createJsonWebKey(JsonObject jsonObject) throws GeneralSecurityException {
        try {
            return JsonWebKey.Factory.newJwk(JsonUtil.parseJson(jsonObject.toString()));
        } catch (JoseException e) {
            throw new GeneralSecurityException("Unable to create JsonWebKey", e);
        }
    }

    /**
     * Decode a PEM encoded public key string to an RSA PublicKey
     *
     * @param pemEncoded - PEM string for public key
     * @return PublicKey
     * @throws GeneralSecurityException on decode failure
     */
    public static PublicKey decodePublicKey(String pemEncoded) throws GeneralSecurityException {
        pemEncoded = removeKeyBeginEnd(pemEncoded);
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
    private static String removeKeyBeginEnd(String pem) {
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

    private KeyUtils() {
    }
}
