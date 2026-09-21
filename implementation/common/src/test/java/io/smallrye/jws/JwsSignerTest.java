package io.smallrye.jws;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.crypto.SecretKey;

import org.junit.Test;

import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.util.KeyUtils;

public class JwsSignerTest {

    private static final String CONTENT = "{\"sub\":\"alice\"}";

    @Test
    public void signWithRsaKey() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair(2048);

        String jws = JwsSigner.builder(keyPair.getPrivate())
                .algorithm("RS256")
                .keyId("key-1")
                .type("JWT")
                .build()
                .sign(CONTENT);

        JsonWebSignature parsed = JsonWebSignature.parse(jws);
        assertEquals("RS256", parsed.headers().algorithm());
        assertEquals("key-1", parsed.headers().keyId());
        assertEquals("JWT", parsed.headers().type());

        assertEquals(CONTENT, JwsVerifier.builder(keyPair.getPublic()).algorithm("RS256").build().verify(jws));
    }

    @Test
    public void signWithSecretKey() throws Exception {
        SecretKey secretKey = KeyUtils.generateSecretKey(SignatureAlgorithm.HS256);

        String jws = JwsSigner.builder(secretKey)
                .algorithm("HS256")
                .build()
                .sign(CONTENT);

        assertEquals(CONTENT, JwsVerifier.builder(secretKey).algorithm("HS256").build().verify(jws));
    }

    @Test
    public void signWithRegisteredHeaders() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair(2048);
        String thumbprint = "S1KJRhqXaGe4sOGZLzTvGxCQgvKi0-6SkR1n5ZsMGRs";

        String jws = JwsSigner.builder(keyPair.getPrivate())
                .algorithm("RS256")
                .header("jku", "https://server.com/jwks")
                .header("x5t#S256", thumbprint)
                .header("custom-header", "custom-value")
                .build()
                .sign(CONTENT);

        JsonWebSignature parsed = JsonWebSignature.parse(jws);
        assertEquals(thumbprint, parsed.headers().x509CertificateSha256Thumbprint());
        assertEquals("https://server.com/jwks", parsed.headers().header("jku"));
        assertEquals("custom-value", parsed.headers().header("custom-header"));

        assertEquals(CONTENT, JwsVerifier.builder(keyPair.getPublic()).algorithm("RS256").build().verify(jws));
    }

    @Test
    public void signWithShortRsaKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        JwsSigner signer = JwsSigner.builder(keyPair.getPrivate()).algorithm("RS256").build();
        JwsException ex = assertThrows(JwsException.class, () -> signer.sign(CONTENT));
        assertTrue(ex.getMessage().contains("The RSA key size must be at least 2048 bits"));
    }

    @Test
    public void signWithShortRsaKeyAndRelaxedValidation() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        String jws = JwsSigner.builder(keyPair.getPrivate())
                .algorithm("RS256")
                .relaxKeyValidation(true)
                .build()
                .sign(CONTENT);

        assertEquals(CONTENT, JwsVerifier.builder(keyPair.getPublic()).algorithm("RS256").build().verify(jws));
    }

    @Test
    public void signatureAlgorithmIsRequired() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair(2048);

        JwsException ex = assertThrows(JwsException.class, () -> JwsSigner.builder(keyPair.getPrivate()).build());
        assertEquals("Signature algorithm is not set", ex.getMessage());
    }

    @Test
    public void signingKeyIsRequired() throws Exception {
        JwsException ex = assertThrows(JwsException.class, () -> JwsSigner.builder(null).algorithm("RS256").build());
        assertEquals("Signing key is not set", ex.getMessage());
    }
}
