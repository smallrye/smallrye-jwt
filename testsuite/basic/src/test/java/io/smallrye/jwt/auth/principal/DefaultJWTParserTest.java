package io.smallrye.jwt.auth.principal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collections;

import javax.crypto.SecretKey;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OctetKeyPairJsonWebKey;
import org.jose4j.jwk.OkpJwkGenerator;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.UnresolvableKeyException;
import org.junit.jupiter.api.Test;

import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.util.KeyUtils;
import io.smallrye.jwt.util.ResourceUtils;

class DefaultJWTParserTest {
    @Test
    void parseWithConfiguredPublicKey() throws Exception {
        String jwtString = Jwt.upn("jdoe@example.com").issuer("https://server.example.com")
                .sign(KeyUtils.readPrivateKey("/privateKey.pem"));
        JWTAuthContextInfo config = new JWTAuthContextInfo("/publicKey.pem", "https://server.example.com");
        JWTParser parser = new DefaultJWTParser(config);
        JsonWebToken jwt = parser.parse(jwtString);
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    void parseWithConfiguredCert() throws Exception {
        String jwtString = Jwt.upn("jdoe@example.com").issuer("https://server.example.com")
                .sign(KeyUtils.readPrivateKey("/privateKey2.pem"));
        JWTAuthContextInfo config = new JWTAuthContextInfo("/certificate.pem", "https://server.example.com");
        JWTParser parser = new DefaultJWTParser(config);
        JsonWebToken jwt = parser.parse(jwtString);
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    void parseWithConfiguredCertAndThumbprint() throws Exception {
        X509Certificate cert = KeyUtils.getCertificate(ResourceUtils.readResource("/certificate.pem"));
        String jwtString = Jwt.upn("jdoe@example.com").issuer("https://server.example.com")
                .jws().thumbprint(cert)
                .sign(KeyUtils.readPrivateKey("/privateKey2.pem"));
        JWTAuthContextInfo config = new JWTAuthContextInfo("/certificate.pem", "https://server.example.com");
        config.setVerifyCertificateThumbprint(true);
        JWTParser parser = new DefaultJWTParser(config);
        JsonWebToken jwt = parser.parse(jwtString);
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    void parseWithConfiguredCertAndThumbprintS256() throws Exception {
        X509Certificate cert = KeyUtils.getCertificate(ResourceUtils.readResource("/certificate.pem"));
        String jwtString = Jwt.upn("jdoe@example.com").issuer("https://server.example.com")
                .jws().thumbprintS256(cert)
                .sign(KeyUtils.readPrivateKey("/privateKey2.pem"));
        JWTAuthContextInfo config = new JWTAuthContextInfo("/certificate.pem", "https://server.example.com");
        config.setVerifyCertificateThumbprint(true);
        JWTParser parser = new DefaultJWTParser(config);
        JsonWebToken jwt = parser.parse(jwtString);
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    void parseWithConfiguredCertAndThumbprintMissing() throws Exception {
        String jwtString = Jwt.upn("jdoe@example.com").issuer("https://server.example.com")
                .sign(KeyUtils.readPrivateKey("/privateKey2.pem"));
        JWTAuthContextInfo config = new JWTAuthContextInfo("/certificate.pem", "https://server.example.com");
        config.setVerifyCertificateThumbprint(true);
        JWTParser parser = new DefaultJWTParser(config);
        ParseException thrown = assertThrows(ParseException.class, () -> parser.parse(jwtString),
                "UnresolvableKeyException is expected");
        assertTrue(thrown.getCause() instanceof UnresolvableKeyException);
    }

    @Test
    void parseWithCustomContext() throws Exception {
        String jwtString = Jwt.upn("jdoe@example.com").issuer("https://server.example.com")
                .sign(KeyUtils.readPrivateKey("/privateKey.pem"));
        JWTAuthContextInfo config = new JWTAuthContextInfo("/publicKey.pem", "https://server.example.com");
        JsonWebToken jwt = new DefaultJWTParser().parse(jwtString, config);
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    void verifyWithRsaPublicKey() throws Exception {
        String jwtString = Jwt.upn("jdoe@example.com").sign(KeyUtils.readPrivateKey("/privateKey.pem"));
        JsonWebToken jwt = new DefaultJWTParser().verify(jwtString, KeyUtils.readPublicKey("/publicKey.pem"));
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    void verifyWithEcPublicKey() throws Exception {
        String jwtString = Jwt.upn("jdoe@example.com").sign(
                KeyUtils.readPrivateKey("/ecPrivateKey.pem", SignatureAlgorithm.ES256));
        JsonWebToken jwt = new DefaultJWTParser().verify(jwtString,
                KeyUtils.readPublicKey("/ecPublicKey.pem", SignatureAlgorithm.ES256));
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    void verifyWithEdEcPublicKey() throws Exception {
        if (Runtime.version().version().get(0) >= 17) {
            String jwtString = Jwt.upn("jdoe@example.com").sign("/edEcPrivateKey.jwk");
            JsonWebToken jwt = new DefaultJWTParser().verify(jwtString, getEdEcPublicKey());
            assertEquals("jdoe@example.com", jwt.getName());
        }
    }

    private static PublicKey getEdEcPublicKey() throws Exception {
        String keyContent = KeyUtils.readKeyContent("/edEcPublicKey.jwk");
        return PublicJsonWebKey.Factory.newPublicJwk(keyContent).getPublicKey();
    }

    @Test
    void verifyWithRsaAndEcKeys() throws Exception {
        String jwtString = Jwt.upn("jdoe@example.com").sign(KeyUtils.readPrivateKey("/privateKey.pem"));
        JWTParser parser = new DefaultJWTParser();
        JsonWebToken jwt = parser.verify(jwtString, KeyUtils.readPublicKey("/publicKey.pem"));
        assertEquals("jdoe@example.com", jwt.getName());

        jwtString = Jwt.upn("jdoe@example.com").sign(
                KeyUtils.readPrivateKey("/ecPrivateKey.pem", SignatureAlgorithm.ES256));
        jwt = parser.verify(jwtString,
                KeyUtils.readPublicKey("/ecPublicKey.pem", SignatureAlgorithm.ES256));
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    void verifyWithRsaAndEcKeysWithInjectedFactory() throws Exception {
        String jwtString = Jwt.upn("jdoe@example.com").sign(KeyUtils.readPrivateKey("/privateKey.pem"));
        JWTParser parser = new DefaultJWTParser(new DefaultJWTCallerPrincipalFactory());
        JsonWebToken jwt = parser.verify(jwtString, KeyUtils.readPublicKey("/publicKey.pem"));
        assertEquals("jdoe@example.com", jwt.getName());

        jwtString = Jwt.upn("jdoe@example.com").sign(
                KeyUtils.readPrivateKey("/ecPrivateKey.pem", SignatureAlgorithm.ES256));
        jwt = parser.verify(jwtString,
                KeyUtils.readPublicKey("/ecPublicKey.pem", SignatureAlgorithm.ES256));
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    void verifyWithRsaAndEcKeysWithInjectedFactoryAndKeyLocation() throws Exception {
        String jwtString = Jwt.upn("jdoe@example.com").issuer("https://server.example.com")
                .sign(KeyUtils.readPrivateKey("/privateKey.pem"));
        JWTParser parser = new DefaultJWTParser(new DefaultJWTCallerPrincipalFactory());
        JsonWebToken jwt = parser.parse(jwtString, new JWTAuthContextInfo("/publicKey.pem", "https://server.example.com"));
        assertEquals("jdoe@example.com", jwt.getName());

        jwtString = Jwt.upn("jdoe@example.com").issuer("https://server.example.com").sign(
                KeyUtils.readPrivateKey("/ecPrivateKey.pem", SignatureAlgorithm.ES256));
        JWTAuthContextInfo context = new JWTAuthContextInfo("/ecPublicKey.pem", "https://server.example.com");
        context.setSignatureAlgorithm(SignatureAlgorithm.ES256);
        jwt = parser.parse(jwtString, context);
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    void verifyWithSecretKey() throws Exception {
        SecretKey secretKey = createSecretKey();
        String jwtString = Jwt.upn("jdoe@example.com").sign(secretKey);
        JsonWebToken jwt = new DefaultJWTParser().verify(jwtString, secretKey);
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    void verifyWithSecretString() throws Exception {
        String secret = "AyM1SysPpbyDfgZld3umj1qzKObwVMko";
        String jwtString = Jwt.upn("jdoe@example.com").signWithSecret(secret);
        JsonWebToken jwt = new DefaultJWTParser().verify(jwtString, secret);
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    void decryptWithRsaPrivateKey() throws Exception {
        String jwtString = Jwt.upn("jdoe@example.com")
                .jwe()
                .encrypt(KeyUtils.readEncryptionPublicKey("/publicKey.pem"));
        JsonWebToken jwt = new DefaultJWTParser().decrypt(jwtString, KeyUtils.readDecryptionPrivateKey("/privateKey.pem"));
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    void decryptWithRsaPrivateKeyRsaOaep256() throws Exception {
        String jwtString = Jwt.upn("jdoe@example.com")
                .jwe().keyAlgorithm(KeyEncryptionAlgorithm.RSA_OAEP_256)
                .encrypt(KeyUtils.readEncryptionPublicKey("/publicKey.pem"));

        JWTAuthContextInfo config = new JWTAuthContextInfo();
        config.setDecryptionKeyLocation("/privateKey.pem");
        config.setKeyEncryptionAlgorithm(Collections.singleton(KeyEncryptionAlgorithm.RSA_OAEP_256));
        JsonWebToken jwt = new DefaultJWTParser().parse(jwtString, config);

        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    void decryptWithRsaPrivateKeyInnerSigned() throws Exception {
        String jwtString = Jwt.upn("jdoe@example.com")
                .innerSign(KeyUtils.readPrivateKey(("/privateKey.pem")))
                .encrypt(KeyUtils.readEncryptionPublicKey("/publicKey.pem"));

        JWTAuthContextInfo config = new JWTAuthContextInfo();
        config.setDecryptionKeyLocation("/privateKey.pem");
        config.setPublicKeyLocation("/publicKey.pem");
        config.setKeyEncryptionAlgorithm(Collections.singleton(KeyEncryptionAlgorithm.RSA_OAEP));
        JsonWebToken jwt = new DefaultJWTParser().parse(jwtString, config);

        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    void decryptWithRsaPrivateKeyInJwkFormat() throws Exception {
        String content = ResourceUtils.readResource("/encryptPublicKey.jwk");
        PublicJsonWebKey jwk = (PublicJsonWebKey) KeyUtils.loadJsonWebKeys(content).get(0);
        String jwtString = Jwt.upn("jdoe@example.com")
                .jwe().keyAlgorithm(KeyEncryptionAlgorithm.RSA_OAEP)
                .encrypt(jwk.getPublicKey());

        JWTAuthContextInfo config = new JWTAuthContextInfo();
        config.setDecryptionKeyLocation("/decryptPrivateKey.jwk");

        JsonWebToken jwt = new DefaultJWTParser().parse(jwtString, config);
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    void decryptWithEcPrivateKey() throws Exception {
        String jwtString = Jwt.upn("jdoe@example.com").jwe().encrypt(
                KeyUtils.readEncryptionPublicKey("/ecPublicKey.pem", KeyEncryptionAlgorithm.ECDH_ES_A256KW));
        JsonWebToken jwt = new DefaultJWTParser().decrypt(jwtString,
                KeyUtils.readDecryptionPrivateKey("/ecPrivateKey.pem", KeyEncryptionAlgorithm.ECDH_ES_A256KW));
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    void decryptWithEcPrivateKeyX25519() throws Exception {
        if (Runtime.version().version().get(0) >= 17) {
            OctetKeyPairJsonWebKey jwk = OkpJwkGenerator.generateJwk(OctetKeyPairJsonWebKey.SUBTYPE_X25519);
            String jwtString = Jwt.upn("jdoe@example.com").jwe().encrypt(jwk.getPublicKey());
            JsonWebToken jwt = new DefaultJWTParser().decrypt(jwtString, jwk.getPrivateKey());
            assertEquals("jdoe@example.com", jwt.getName());
        }
    }

    @Test
    void decryptWithSecretKey() throws Exception {
        SecretKey secretKey = createSecretKey();
        String jwtString = Jwt.upn("jdoe@example.com").jwe().encrypt(secretKey);
        JsonWebToken jwt = new DefaultJWTParser().decrypt(jwtString, secretKey);
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    void decryptWithSecretString() throws Exception {
        String secret = "AyM1SysPpbyDfgZld3umj1qzKObwVMko";
        String jwtString = Jwt.upn("jdoe@example.com").jwe().encryptWithSecret(secret);
        JsonWebToken jwt = new DefaultJWTParser().decrypt(jwtString, secret);
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    void decryptVerifyWithSecretKey() throws Exception {
        SecretKey secretKey = createSecretKey();
        String jwtString = Jwt.upn("jdoe@example.com")
                .innerSign(secretKey)
                .encrypt(secretKey);
        JWTAuthContextInfo config = new JWTAuthContextInfo();
        config.setSecretDecryptionKey(secretKey);
        config.setKeyEncryptionAlgorithm(Collections.singleton(KeyEncryptionAlgorithm.A256KW));
        config.setSecretVerificationKey(secretKey);
        config.setSignatureAlgorithm(SignatureAlgorithm.HS256);
        JsonWebToken jwt = new DefaultJWTParser().parse(jwtString, config);
        assertEquals("jdoe@example.com", jwt.getName());
    }

    private static SecretKey createSecretKey() throws Exception {
        String jwkJson = "{\"kty\":\"oct\",\"k\":\"Fdh9u8rINxfivbrianbbVT1u232VQBZYKx1HGAGPt2I\"}";
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(jwkJson);
        return (SecretKey) jwk.getKey();
    }

    @Test
    void parseExpiredTokenWithDefaultExpiryGrace() throws Exception {
        // default is 60 secs
        String jwtString = Jwt.upn("jdoe@example.com").issuer("https://server.example.com")
                .issuedAt(Instant.now().minusSeconds(100))
                .expiresAt(Instant.now().minusSeconds(20))
                .sign(KeyUtils.readPrivateKey("/privateKey.pem"));
        JWTAuthContextInfo config = new JWTAuthContextInfo("/publicKey.pem", "https://server.example.com");
        JsonWebToken jwt = new DefaultJWTParser(config).parse(jwtString);
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    void parseExpiredToken() throws Exception {
        String jwtString = Jwt.upn("jdoe@example.com").issuer("https://server.example.com")
                .issuedAt(Instant.now().minusSeconds(100))
                .expiresAt(Instant.now().minusSeconds(80))
                .sign(KeyUtils.readPrivateKey("/privateKey.pem"));
        JWTAuthContextInfo config = new JWTAuthContextInfo("/publicKey.pem", "https://server.example.com");
        ParseException thrown = assertThrows(ParseException.class, () -> new DefaultJWTParser().parse(jwtString, config),
                "UnresolvableKeyException is expected");
        assertEquals(ErrorCodes.EXPIRED, ((InvalidJwtException) thrown.getCause()).getErrorDetails().get(0).getErrorCode());
    }

    @Test
    void parseExpiredTokenWithZeroExpiryGrace() throws Exception {
        String jwtString = Jwt.upn("jdoe@example.com").issuer("https://server.example.com")
                .issuedAt(Instant.now().minusSeconds(100))
                .expiresAt(Instant.now().minusSeconds(80))
                .sign(KeyUtils.readPrivateKey("/privateKey.pem"));
        JWTAuthContextInfo config = new JWTAuthContextInfo("/publicKey.pem", "https://server.example.com");
        config.setExpGracePeriodSecs(0);
        ParseException thrown = assertThrows(ParseException.class, () -> new DefaultJWTParser().parse(jwtString, config),
                "UnresolvableKeyException is expected");
        assertEquals(ErrorCodes.EXPIRED, ((InvalidJwtException) thrown.getCause()).getErrorDetails().get(0).getErrorCode());
    }
}
