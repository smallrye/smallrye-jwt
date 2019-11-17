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
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;

/**
 * Utility methods for dealing with decoding public and private keys resources
 */
public class KeyUtils {
    private static final String RSA = "RSA";
    private static final String EC = "EC";

    public static PrivateKey readPrivateKey(String pemResName, SignatureAlgorithm algo)
            throws IOException, GeneralSecurityException {
        InputStream contentIS = KeyUtils.class.getResourceAsStream(pemResName);
        byte[] tmp = new byte[4096];
        int length = contentIS.read(tmp);
        return decodePrivateKey(new String(tmp, 0, length), algo);
    }

    public static PublicKey readPublicKey(String pemResName, SignatureAlgorithm algo)
            throws IOException, GeneralSecurityException {
        InputStream contentIS = KeyUtils.class.getResourceAsStream(pemResName);
        byte[] tmp = new byte[4096];
        int length = contentIS.read(tmp);
        return decodePublicKey(new String(tmp, 0, length), algo);
    }

    public static KeyPair generateKeyPair(int keySize, SignatureAlgorithm algo) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm(algo));
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.genKeyPair();
    }

    public static String keyAlgorithm(SignatureAlgorithm algo) throws NoSuchAlgorithmException {
        if (algo.name().startsWith("RS")) {
            return RSA;
        }
        if (algo.name().startsWith("ES")) {
            return EC;
        }

        throw new NoSuchAlgorithmException("Unsupported key type" + algo.name());

    }

    /**
     * Decode a PEM RSA private key
     * 
     * @param pemEncoded - pem string for key
     * @param algo - decoding key algorithm
     * @return RSA private key instance
     * @throws GeneralSecurityException - on failure to decode and create key
     */
    public static PrivateKey decodePrivateKey(String pemEncoded, SignatureAlgorithm algo) throws GeneralSecurityException {
        pemEncoded = removeKeyBeginEnd(pemEncoded);
        byte[] pkcs8EncodedBytes = Base64.getDecoder().decode(pemEncoded);

        // extract the private key

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
        KeyFactory kf = KeyFactory.getInstance(keyAlgorithm(algo));
        return kf.generatePrivate(keySpec);
    }

    /**
     * Decode a JWK(S) encoded public key string to an RSA PublicKey. This assumes a single JWK in the set as
     * only the first JWK is used.
     * 
     * @param jwksValue - JWKS string value
     * @param algo - decoding key algorithm
     * @return PublicKey from RSAPublicKeySpec
     * @throws GeneralSecurityException when RSA security is not supported or public key cannot be decoded
     */
    public static PublicKey decodeJWKSPublicKey(String jwksValue, SignatureAlgorithm algo) throws GeneralSecurityException {
        JsonObject jwks;

        try (Reader reader = new StringReader(jwksValue); JsonReader json = Json.createReader(reader)) {
            jwks = json.readObject();
        } catch (Exception e) {
            // See if this is base64 encoded
            byte[] decoded = Base64.getDecoder().decode(jwksValue);

            try (InputStream stream = new ByteArrayInputStream(decoded); JsonReader json = Json.createReader(stream)) {
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

        String keyAlgorithm = keyAlgorithm(algo);
        KeyFactory kf = KeyFactory.getInstance(keyAlgorithm);
        if (EC.equals(keyAlgorithm)) {
            String x = jwk.getString("x");
            String y = jwk.getString("y");
            String crv = jwk.getString("crv");

            byte[] xbytes = Base64.getUrlDecoder().decode(x);
            BigInteger xint = new BigInteger(1, xbytes);
            byte[] ybytes = Base64.getUrlDecoder().decode(y);
            BigInteger yint = new BigInteger(1, ybytes);
            String stdName = String.format("secp%03dr1", Integer.parseInt(crv.split("P-")[1]));
            AlgorithmParameters parameters = AlgorithmParameters.getInstance(EC);
            parameters.init(new ECGenParameterSpec(stdName));
            ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(new ECPoint(xint, yint),
                    parameters.getParameterSpec(ECParameterSpec.class));
            return kf.generatePublic(ecPublicKeySpec);
        } else {
            String e = jwk.getString("e");
            String n = jwk.getString("n");

            byte[] ebytes = Base64.getUrlDecoder().decode(e);
            BigInteger publicExponent = new BigInteger(1, ebytes);
            byte[] nbytes = Base64.getUrlDecoder().decode(n);
            BigInteger modulus = new BigInteger(1, nbytes);
            RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
            return kf.generatePublic(rsaPublicKeySpec);
        }
    }

    /**
     * Decode a PEM encoded public key string to an RSA PublicKey
     * 
     * @param pemEncoded - PEM string for public key
     * @param algo - decoding key algorithm
     * @return PublicKey
     * @throws GeneralSecurityException on decode failure
     */
    public static PublicKey decodePublicKey(String pemEncoded, SignatureAlgorithm algo) throws GeneralSecurityException {
        pemEncoded = removeKeyBeginEnd(pemEncoded);
        byte[] encodedBytes = Base64.getDecoder().decode(pemEncoded);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(encodedBytes);
        KeyFactory kf = KeyFactory.getInstance(keyAlgorithm(algo));
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
        return CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(encodedBytes))
                .getPublicKey();
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
