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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.crypto.SecretKey;

import org.jose4j.jwk.JsonWebKey;

import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;

/**
 * Utility methods for dealing with decoding public and private keys resources
 */
@Deprecated
public final class KeyUtils {

    private KeyUtils() {
    }

    public static PrivateKey readPrivateKey(String pemResName) throws IOException, GeneralSecurityException {
        return io.smallrye.jwt.util.KeyUtils.readPrivateKey(pemResName);
    }

    public static PrivateKey readPrivateKey(String pemResName, SignatureAlgorithm algo)
            throws IOException, GeneralSecurityException {
        return io.smallrye.jwt.util.KeyUtils.readPrivateKey(pemResName, algo);
    }

    public static PrivateKey readDecryptionPrivateKey(String pemResName) throws IOException, GeneralSecurityException {
        return io.smallrye.jwt.util.KeyUtils.readDecryptionPrivateKey(pemResName);
    }

    public static PrivateKey readDecryptionPrivateKey(String pemResName, KeyEncryptionAlgorithm algo)
            throws IOException, GeneralSecurityException {
        return io.smallrye.jwt.util.KeyUtils.readDecryptionPrivateKey(pemResName, algo);
    }

    public static PublicKey readPublicKey(String pemResName) throws IOException, GeneralSecurityException {
        return io.smallrye.jwt.util.KeyUtils.readPublicKey(pemResName);
    }

    public static PublicKey readPublicKey(String pemResName, SignatureAlgorithm algo)
            throws IOException, GeneralSecurityException {
        return io.smallrye.jwt.util.KeyUtils.readPublicKey(pemResName, algo);
    }

    public static PublicKey readEncryptionPublicKey(String pemResName) throws IOException, GeneralSecurityException {
        return io.smallrye.jwt.util.KeyUtils.readEncryptionPublicKey(pemResName);
    }

    public static PublicKey readEncryptionPublicKey(String pemResName, KeyEncryptionAlgorithm algo)
            throws IOException, GeneralSecurityException {
        return io.smallrye.jwt.util.KeyUtils.readEncryptionPublicKey(pemResName, algo);
    }

    public static KeyPair generateKeyPair(int keySize) throws NoSuchAlgorithmException {
        return io.smallrye.jwt.util.KeyUtils.generateKeyPair(keySize);
    }

    public static KeyPair generateKeyPair(int keySize, SignatureAlgorithm algo) throws NoSuchAlgorithmException {
        return io.smallrye.jwt.util.KeyUtils.generateKeyPair(keySize, algo);
    }

    /**
     * Decode a PEM RSA private key
     * 
     * @param pemEncoded - pem string for key
     * @return RSA private key instance
     * @throws GeneralSecurityException - on failure to decode and create key
     */
    public static PrivateKey decodePrivateKey(String pemEncoded) throws GeneralSecurityException {
        return io.smallrye.jwt.util.KeyUtils.decodePrivateKey(pemEncoded);
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
        return io.smallrye.jwt.util.KeyUtils.decodePrivateKey(pemEncoded, algo);
    }

    /**
     * Decode a decryption PEM private key
     *
     * @param pemEncoded - pem string for key
     * @return Private key instance
     * @throws GeneralSecurityException - on failure to decode and create key
     */
    public static PrivateKey decodeDecryptionPrivateKey(String pemEncoded) throws GeneralSecurityException {
        return io.smallrye.jwt.util.KeyUtils.decodeDecryptionPrivateKey(pemEncoded);
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
        return io.smallrye.jwt.util.KeyUtils.decodeDecryptionPrivateKey(pemEncoded, algo);
    }

    /**
     * Decode a PEM encoded public key string to an RSA PublicKey
     * 
     * @param pemEncoded - PEM string for public key
     * @return PublicKey
     * @throws GeneralSecurityException on decode failure
     */
    public static PublicKey decodePublicKey(String pemEncoded) throws GeneralSecurityException {
        return io.smallrye.jwt.util.KeyUtils.decodePublicKey(pemEncoded);
    }

    public static SecretKey createSecretKeyFromSecret(String secret) {
        return io.smallrye.jwt.util.KeyUtils.createSecretKeyFromSecret(secret);
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
        return io.smallrye.jwt.util.KeyUtils.decodePublicKey(pemEncoded, algo);
    }

    public static PublicKey decodeEncryptionPublicKey(String pemEncoded, KeyEncryptionAlgorithm algo)
            throws GeneralSecurityException {
        return io.smallrye.jwt.util.KeyUtils.decodeEncryptionPublicKey(pemEncoded, algo);
    }

    /**
     * Decode a PEM encoded certificate string to an RSA PublicKey
     * 
     * @param pemEncoded - PEM string for certificate
     * @return PublicKey
     * @throws GeneralSecurityException on decode failure
     */
    public static PublicKey decodeCertificate(String pemEncoded) throws GeneralSecurityException {
        return io.smallrye.jwt.util.KeyUtils.decodeCertificate(pemEncoded);
    }

    /**
     * Decode a PEM encoded certificate string to X509Certificate
     *
     * @param pemEncoded - PEM string for certificate
     * @return X509Certificate
     * @throws GeneralSecurityException on decode failure
     */
    public static X509Certificate getCertificate(String pemEncoded) throws GeneralSecurityException {
        return io.smallrye.jwt.util.KeyUtils.getCertificate(pemEncoded);
    }

    /**
     * Strip any -----BEGIN*KEY... header and -----END*KEY... footer and newlines
     * 
     * @param pem encoded string with option header/footer
     * @return a single base64 encoded pem string
     */
    public static String removePemKeyBeginEnd(String pem) {
        return io.smallrye.jwt.util.KeyUtils.removePemKeyBeginEnd(pem);
    }

    public static List<JsonWebKey> loadJsonWebKeys(String content) {
        return io.smallrye.jwt.util.KeyUtils.loadJsonWebKeys(content);
    }

    public static Key readEncryptionKey(String location, String kid) throws IOException {
        return io.smallrye.jwt.util.KeyUtils.readEncryptionKey(location, kid);
    }

    public static Key readSigningKey(String location, String kid) throws IOException {
        return io.smallrye.jwt.util.KeyUtils.readSigningKey(location, kid);
    }
}
