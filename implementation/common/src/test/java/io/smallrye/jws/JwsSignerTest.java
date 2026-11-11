package io.smallrye.jws;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import javax.crypto.SecretKey;

import org.junit.Test;

import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.util.KeyUtils;

public class JwsSignerTest {

    private static final String CERTIFICATE = "-----BEGIN CERTIFICATE-----\n"
            + "MIIC9DCCAdygAwIBAgIJAO0Y7B7dV9KpMA0GCSqGSIb3DQEBCwUAMA8xDTALBgNV\n"
            + "BAMMBHRlc3QwHhcNMjAwODI1MTIzOTA1WhcNMjEwODI1MTIzOTA1WjAPMQ0wCwYD\n"
            + "VQQDDAR0ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsl8Cqii/\n"
            + "4UFg5Lq3R8kZ//Wmapq4KQn4k+foEOymfUbw44E6pCU+iCK0RbyKXgTMErMN3ZFD\n"
            + "xpoDdSeEDoS2kdlRF4XNtFG8RW6+h1wLJGRj7gi9bc0Vg5CzTGWhDvI6oT23KtUa\n"
            + "OBjIWknZtLAR5nEJ7vMADq3QKMHcxofx1GmmAQ2NDmVQJvTfM8wV02oZ2vX6yQjB\n"
            + "6t3vbMyIr+h2GU8teu9v/oUf9A9R2Pm6qULSZ80qyo5BXlwwG2D4HsGCxCdg5PqK\n"
            + "Oi9SOkvlE65eBUR8NXxwHdou+SQ/ry//MPwLSpHo9AggVEmSYlfigyVo5w1FUVo6\n"
            + "uYUG/abuKhCSoQIDAQABo1MwUTAdBgNVHQ4EFgQUcDgMETNCuUuEGWzKoXjrvS8+\n"
            + "kQAwHwYDVR0jBBgwFoAUcDgMETNCuUuEGWzKoXjrvS8+kQAwDwYDVR0TAQH/BAUw\n"
            + "AwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAH0o4kU37vc7OR/+fPQJdrBQqQaukq5ri\n"
            + "yuMSTrU1vSizEXpd0RFE8moSks6+Vh4mEzU7zLAU54N6glcGItEmBko5xgTuQRgd\n"
            + "b0LtR7Bu28QKfRRJxZ9GnGxinDPtFPD+7oTXZfI2Ed/RAuVlbppEBr2Pr2eO9B1x\n"
            + "fgYJNwA1K/XA38G7njxQ/wcpgOp/iFdV7dyR6CyAtwkD92sMnEZKPVz3trBT9DFM\n"
            + "5mynDFn9PHYVB7R5mUjIc7C9yskHGIsqqSBAfsxUqKfCS2NlWjn4+JZ8BYPLgy6X\n"
            + "hlGxh5zhvJPoT6J9+gA5l1Z2xMXI08ym8quIIUJNoYovSf8x4bXVjQ==\n"
            + "-----END CERTIFICATE-----";
    private static final String CONTENT = "{\"sub\":\"alice\"}";

    @Test
    public void signWithRsaKey() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair(2048);

        String jws = JwsSigner.builder(keyPair.getPrivate())
                .algorithm(SignatureAlgorithm.RS256)
                .keyId("key-1")
                .type("JWT")
                .build()
                .sign(CONTENT);

        JsonWebSignature parsed = JsonWebSignature.parse(jws);
        assertEquals("RS256", parsed.headers().algorithm());
        assertEquals("key-1", parsed.headers().keyId());
        assertEquals("JWT", parsed.headers().type());

        assertEquals(CONTENT, JwsVerifier.builder(keyPair.getPublic()).algorithm(SignatureAlgorithm.RS256).build().verify(jws));
    }

    @Test
    public void signWithSecretKey() throws Exception {
        SecretKey secretKey = KeyUtils.generateSecretKey(SignatureAlgorithm.HS256);

        String jws = JwsSigner.builder(secretKey)
                .algorithm(SignatureAlgorithm.HS256)
                .build()
                .sign(CONTENT);

        assertEquals(CONTENT, JwsVerifier.builder(secretKey).algorithm(SignatureAlgorithm.HS256).build().verify(jws));
    }

    @Test
    public void signWithRegisteredHeaders() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair(2048);
        String thumbprint = "S1KJRhqXaGe4sOGZLzTvGxCQgvKi0-6SkR1n5ZsMGRs";

        String jws = JwsSigner.builder(keyPair.getPrivate())
                .algorithm(SignatureAlgorithm.RS256)
                .header("jku", "https://server.com/jwks")
                .header("x5t#S256", thumbprint)
                .header("custom-header", "custom-value")
                .build()
                .sign(CONTENT);

        JsonWebSignature parsed = JsonWebSignature.parse(jws);
        assertEquals(thumbprint, parsed.headers().x509CertificateSha256Thumbprint());
        assertEquals("https://server.com/jwks", parsed.headers().header("jku"));
        assertEquals("custom-value", parsed.headers().header("custom-header"));

        assertEquals(CONTENT, JwsVerifier.builder(keyPair.getPublic()).algorithm(SignatureAlgorithm.RS256).build().verify(jws));
    }

    @Test
    public void signWithShortRsaKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        JwsSigner signer = JwsSigner.builder(keyPair.getPrivate()).algorithm(SignatureAlgorithm.RS256).build();
        JwsException ex = assertThrows(JwsException.class, () -> signer.sign(CONTENT));
        assertTrue(ex.getMessage().contains("The RSA key size must be at least 2048 bits"));
    }

    @Test
    public void signWithShortRsaKeyAndRelaxedValidation() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        String jws = JwsSigner.builder(keyPair.getPrivate())
                .algorithm(SignatureAlgorithm.RS256)
                .relaxKeyValidation(true)
                .build()
                .sign(CONTENT);

        assertEquals(CONTENT, JwsVerifier.builder(keyPair.getPublic()).algorithm(SignatureAlgorithm.RS256).build().verify(jws));
    }

    @Test
    public void signatureAlgorithmIsRequired() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair(2048);

        JwsException ex = assertThrows(JwsException.class, () -> JwsSigner.builder(keyPair.getPrivate()).build());
        assertEquals("Signature algorithm is not set", ex.getMessage());
    }

    @Test
    public void signingKeyIsRequired() throws Exception {
        JwsException ex = assertThrows(JwsException.class,
                () -> JwsSigner.builder(null).algorithm(SignatureAlgorithm.RS256).build());
        assertEquals("Signing key is not set", ex.getMessage());
    }

    @Test
    public void signWithCertificateHeaders() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair(2048);
        X509Certificate certificate = KeyUtils.getCertificate(CERTIFICATE);
        String thumbprint = KeyUtils.getCertificateThumbprint(certificate);
        String sha256Thumbprint = KeyUtils.getCertificateSha256Thumbprint(certificate);

        String jws = JwsSigner.builder(keyPair.getPrivate())
                .algorithm(SignatureAlgorithm.RS256)
                .keyId("key-1")
                .type("JWT")
                .contentType("JWT")
                .header("x5t", thumbprint)
                .header("x5t#S256", sha256Thumbprint)
                .header("x5c", List.of(Base64.getEncoder().encodeToString(certificate.getEncoded())))
                .build()
                .sign(CONTENT);

        JwsHeaders headers = JsonWebSignature.parse(jws).headers();
        assertEquals("key-1", headers.keyId());
        assertEquals("RS256", headers.algorithm());
        assertEquals("JWT", headers.type());
        assertEquals("JWT", headers.contentType());
        assertEquals(thumbprint, headers.x509CertificateThumbprint());
        assertEquals(sha256Thumbprint, headers.x509CertificateSha256Thumbprint());
        assertEquals(1, headers.x509CertificateChain().size());
        assertEquals(certificate, headers.x509CertificateChain().get(0));
        assertEquals("key-1", headers.header("kid"));
    }
}
