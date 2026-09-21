package io.smallrye.jwe;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Base64;

import javax.crypto.SecretKey;

import org.junit.Test;

import io.smallrye.jwt.algorithm.ContentEncryptionAlgorithm;
import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.jwt.util.KeyUtils;

public class JweEncrypterDecrypterTest {

    private static final String CONTENT = "{\"state\":\"1234\"}";

    @Test
    public void encryptAndDecryptWithRsaKey() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair(2048);

        String jwe = JweEncrypter.builder(keyPair.getPublic())
                .keyAlgorithm(KeyEncryptionAlgorithm.RSA_OAEP_256)
                .build()
                .encrypt(CONTENT);

        assertEquals(CONTENT, JweDecrypter.builder(keyPair.getPrivate()).build().decrypt(jwe));
    }

    @Test
    public void encryptAndDecryptWithSecretKey() throws Exception {
        SecretKey secretKey = KeyUtils.generateSecretKey(KeyEncryptionAlgorithm.A256KW);

        String jwe = JweEncrypter.builder(secretKey)
                .keyAlgorithm(KeyEncryptionAlgorithm.A256GCMKW)
                .contentAlgorithm(ContentEncryptionAlgorithm.A256GCM)
                .build()
                .encrypt(CONTENT);

        String content = JweDecrypter.builder(secretKey)
                .keyAlgorithm(KeyEncryptionAlgorithm.A256GCMKW)
                .build()
                .decrypt(jwe);
        assertEquals(CONTENT, content);
    }

    @Test
    public void encryptAndDecryptWithDirectSecretKey() throws Exception {
        SecretKey secretKey = KeyUtils.generateSecretKey(KeyEncryptionAlgorithm.A256KW);

        String jwe = JweEncrypter.builder(secretKey)
                .keyAlgorithm(KeyEncryptionAlgorithm.DIR)
                .build()
                .encrypt(CONTENT);

        assertEquals(CONTENT, JweDecrypter.builder(secretKey).build().decrypt(jwe));
    }

    @Test
    public void unexpectedKeyEncryptionAlgorithm() throws Exception {
        SecretKey secretKey = KeyUtils.generateSecretKey(KeyEncryptionAlgorithm.A256KW);

        String jwe = JweEncrypter.builder(secretKey)
                .keyAlgorithm(KeyEncryptionAlgorithm.A256KW)
                .build()
                .encrypt(CONTENT);

        JweDecrypter decrypter = JweDecrypter.builder(secretKey)
                .keyAlgorithm(KeyEncryptionAlgorithm.A256GCMKW)
                .build();
        JweException ex = assertThrows(JweException.class, () -> decrypter.decrypt(jwe));
        assertTrue(ex.getMessage().contains("A256KW"));
    }

    @Test
    public void encryptWithHeaders() throws Exception {
        SecretKey secretKey = KeyUtils.generateSecretKey(KeyEncryptionAlgorithm.A256KW);

        String jwe = JweEncrypter.builder(secretKey)
                .keyAlgorithm(KeyEncryptionAlgorithm.A256KW)
                .keyId("key-1")
                .contentType("JWT")
                .type("JWT")
                .header("custom-header", "custom-value")
                .build()
                .encrypt(CONTENT);

        String headers = new String(Base64.getUrlDecoder().decode(jwe.substring(0, jwe.indexOf('.'))),
                StandardCharsets.UTF_8);
        assertTrue(headers.contains("\"kid\":\"key-1\""));
        assertTrue(headers.contains("\"cty\":\"JWT\""));
        assertTrue(headers.contains("\"typ\":\"JWT\""));
        assertTrue(headers.contains("\"custom-header\":\"custom-value\""));

        assertEquals(CONTENT, JweDecrypter.builder(secretKey).build().decrypt(jwe));
    }

    @Test
    public void encryptWithRegisteredHeaders() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair(2048);
        String thumbprint = "S1KJRhqXaGe4sOGZLzTvGxCQgvKi0-6SkR1n5ZsMGRs";

        String jwe = JweEncrypter.builder(keyPair.getPublic())
                .keyAlgorithm(KeyEncryptionAlgorithm.RSA_OAEP_256)
                .header("jku", "https://server.com/jwks")
                .header("x5t#S256", thumbprint)
                .build()
                .encrypt(CONTENT);

        String headers = new String(Base64.getUrlDecoder().decode(jwe.substring(0, jwe.indexOf('.'))),
                StandardCharsets.UTF_8);
        assertTrue(headers.contains("\"jku\":\"https://server.com/jwks\""));
        assertTrue(headers.contains("\"x5t#S256\":\"" + thumbprint + "\""));

        assertEquals(CONTENT, JweDecrypter.builder(keyPair.getPrivate()).build().decrypt(jwe));
    }

    @Test
    public void decryptParsedSequence() throws Exception {
        SecretKey secretKey = KeyUtils.generateSecretKey(KeyEncryptionAlgorithm.A256KW);

        String sequence = JweEncrypter.builder(secretKey)
                .keyAlgorithm(KeyEncryptionAlgorithm.A256KW)
                .keyId("key-1")
                .contentType("JWT")
                .build()
                .encrypt(CONTENT);

        JsonWebEncryption jwe = JsonWebEncryption.parse(sequence);
        assertEquals(sequence, jwe.serialized());
        assertEquals("key-1", jwe.headers().keyId());
        assertEquals("A256KW", jwe.headers().algorithm());
        assertEquals("A256GCM", jwe.headers().encryptionAlgorithm());
        assertEquals("JWT", jwe.headers().contentType());

        JweDecrypter decrypter = JweDecrypter.builder(secretKey).build();
        assertEquals(CONTENT, decrypter.decrypt(jwe));

        // the sequence can only be decrypted once
        JweException ex = assertThrows(JweException.class, () -> decrypter.decrypt(jwe));
        assertTrue(ex.getMessage().contains("already been decrypted"));
    }

    @Test
    public void invalidSequence() throws Exception {
        SecretKey secretKey = KeyUtils.generateSecretKey(KeyEncryptionAlgorithm.A256KW);
        JweDecrypter decrypter = JweDecrypter.builder(secretKey).build();
        assertThrows(JweException.class, () -> decrypter.decrypt("not-a-jwe-sequence"));
    }

    @Test
    public void keyEncryptionAlgorithmIsRequired() throws Exception {
        SecretKey secretKey = KeyUtils.generateSecretKey(KeyEncryptionAlgorithm.A256KW);
        assertThrows(JweException.class, () -> JweEncrypter.builder(secretKey).build());
    }
}
