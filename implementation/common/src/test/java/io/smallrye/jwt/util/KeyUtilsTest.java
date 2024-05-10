package io.smallrye.jwt.util;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.SecretKey;

import org.junit.Test;

import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;

public class KeyUtilsTest {

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void givenAsymmetricKeyEncryptionAlgo_thenThrowsInvalidAlgorithmException()
            throws InvalidAlgorithmParameterException {
        SecretKey keySpec = KeyUtils.generateSecretKey(KeyEncryptionAlgorithm.RSA_OAEP);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void givenAsymmetricSignatureAlgo_thenThrowsInvalidAlgorithmException() throws InvalidAlgorithmParameterException {
        SecretKey keySpec = KeyUtils.generateSecretKey(SignatureAlgorithm.RS256);
    }

    @Test
    public void generateKeyPairs() throws GeneralSecurityException {
        var keyPair = KeyUtils.generateKeyPair(2048, SignatureAlgorithm.RS256);
        assertTrue(keyPair.getPrivate() instanceof RSAPrivateKey);
        assertTrue(keyPair.getPublic() instanceof RSAPublicKey);

        keyPair = KeyUtils.generateKeyPair(256, SignatureAlgorithm.ES256);
        assertTrue(keyPair.getPrivate() instanceof ECPrivateKey);
        assertTrue(keyPair.getPublic() instanceof ECPublicKey);

        if (Runtime.version().feature() >= 15) {
            keyPair = KeyUtils.generateKeyPair(255, SignatureAlgorithm.EDDSA); // ed25519
            assertTrue(KeyUtils.isSupportedKey(keyPair.getPrivate(), "java.security.interfaces.EdECPrivateKey"));
            assertTrue(KeyUtils.isSupportedKey(keyPair.getPublic(), "java.security.interfaces.EdECPublicKey"));
            keyPair = KeyUtils.generateKeyPair(448, SignatureAlgorithm.EDDSA); // ed448
            assertTrue(KeyUtils.isSupportedKey(keyPair.getPrivate(), "java.security.interfaces.EdECPrivateKey"));
            assertTrue(KeyUtils.isSupportedKey(keyPair.getPublic(), "java.security.interfaces.EdECPublicKey"));
        }
    }

    @Test
    public void decodePrivateKey() throws GeneralSecurityException, IOException {
        String rsaPrivateKeyPem = new String(
                ResourceUtils.getAsClasspathResource("RS256-2048bit-private-key.pem").readAllBytes(),
                StandardCharsets.UTF_8);
        var privateKey = KeyUtils.decodePrivateKey(rsaPrivateKeyPem, SignatureAlgorithm.RS256);
        assertTrue(privateKey instanceof RSAPrivateKey);

        String ecdsaPrivateKeyPem = new String(ResourceUtils.getAsClasspathResource("ES256-private-key.pem").readAllBytes(),
                StandardCharsets.UTF_8);
        privateKey = KeyUtils.decodePrivateKey(ecdsaPrivateKeyPem, SignatureAlgorithm.ES256);
        assertTrue(privateKey instanceof ECPrivateKey);

        if (Runtime.version().feature() >= 15) {
            String ed25519PrivateKeyPem = new String(
                    ResourceUtils.getAsClasspathResource("EDDSA-ED25519-private-key.pem").readAllBytes(),
                    StandardCharsets.UTF_8);
            privateKey = KeyUtils.decodePrivateKey(ed25519PrivateKeyPem, SignatureAlgorithm.EDDSA);
            assertTrue(KeyUtils.isSupportedKey(privateKey, "java.security.interfaces.EdECPrivateKey"));

            String ed448PrivateKeyPem = new String(
                    ResourceUtils.getAsClasspathResource("EDDSA-ED448-private-key.pem").readAllBytes(),
                    StandardCharsets.UTF_8);
            privateKey = KeyUtils.decodePrivateKey(ed448PrivateKeyPem, SignatureAlgorithm.EDDSA);
            assertTrue(KeyUtils.isSupportedKey(privateKey, "java.security.interfaces.EdECPrivateKey"));
        }
    }

    @Test
    public void decodePublicKey() throws GeneralSecurityException, IOException {
        String rsaPublicKeyPem = new String(ResourceUtils.getAsClasspathResource("RS256-2048bit-public-key.pem").readAllBytes(),
                StandardCharsets.UTF_8);
        var publicKey = KeyUtils.decodePublicKey(rsaPublicKeyPem, SignatureAlgorithm.RS256);
        assertTrue(publicKey instanceof RSAPublicKey);

        String ecdsaPublicKeyPem = new String(ResourceUtils.getAsClasspathResource("ES256-public-key.pem").readAllBytes(),
                StandardCharsets.UTF_8);
        publicKey = KeyUtils.decodePublicKey(ecdsaPublicKeyPem, SignatureAlgorithm.ES256);
        assertTrue(publicKey instanceof ECPublicKey);

        if (Runtime.version().feature() >= 15) {
            String ed25519PublicKeyPem = new String(
                    ResourceUtils.getAsClasspathResource("EDDSA-ED25519-public-key.pem").readAllBytes(),
                    StandardCharsets.UTF_8);
            publicKey = KeyUtils.decodePublicKey(ed25519PublicKeyPem, SignatureAlgorithm.EDDSA);
            assertTrue(KeyUtils.isSupportedKey(publicKey, "java.security.interfaces.EdECPublicKey"));

            String ed448PublicKeyPem = new String(
                    ResourceUtils.getAsClasspathResource("EDDSA-ED448-public-key.pem").readAllBytes(),
                    StandardCharsets.UTF_8);
            publicKey = KeyUtils.decodePublicKey(ed448PublicKeyPem, SignatureAlgorithm.EDDSA);
            assertTrue(KeyUtils.isSupportedKey(publicKey, "java.security.interfaces.EdECPublicKey"));
        }
    }
}
