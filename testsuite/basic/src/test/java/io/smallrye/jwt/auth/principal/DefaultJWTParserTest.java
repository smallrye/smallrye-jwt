package io.smallrye.jwt.auth.principal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collections;
import java.util.Set;

import javax.crypto.SecretKey;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

import io.smallrye.jwk.AsymmetricJsonWebKey;
import io.smallrye.jwt.algorithm.EdDSAVerifier;
import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.auth.InvalidJWTException;
import io.smallrye.jwt.auth.TokenExpiredException;
import io.smallrye.jwt.auth.UnresolvableKeyException;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.util.KeyUtils;
import io.smallrye.jwt.util.ResourceUtils;

class DefaultJWTParserTest {
    @Test
    void parseOnly() throws Exception {
        String jwtString = Jwt.upn("jdoe@example.com").sign(KeyUtils.readPrivateKey("/privateKey.pem"));
        JsonWebToken jwt = new DefaultJWTParser().parseOnly(jwtString);
        assertEquals("jdoe@example.com", jwt.getName());
    }

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
        OctetKeyPair okp = (OctetKeyPair) JWK.parse(keyContent);
        return EdDSAVerifier.toPublicKey(okp);
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
        context.setSignatureAlgorithm(Set.of(SignatureAlgorithm.ES256));
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
    void verifyMultipleSignatureAlgorithms() throws Exception {

        JWTAuthContextInfo config = new JWTAuthContextInfo();
        config.setPublicKeyLocation("/signatureJwkSet.jwk");
        config.setSignatureAlgorithm(Set.of(SignatureAlgorithm.RS256, SignatureAlgorithm.ES256));

        String rsaJwt = Jwt.upn("jdoe@example.com").sign("/rs256PrivateKey.jwk");
        JsonWebToken rsaJwtToken = new DefaultJWTParser().parse(rsaJwt, config);
        assertEquals("jdoe@example.com", rsaJwtToken.getName());

        String ecJwt = Jwt.upn("jdoe@example.com").sign("/ecPrivateKey.jwk");
        JsonWebToken ecJwtToken = new DefaultJWTParser().parse(ecJwt, config);
        assertEquals("jdoe@example.com", ecJwtToken.getName());
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
        AsymmetricJsonWebKey jwk = (AsymmetricJsonWebKey) KeyUtils.loadJsonWebKeys(content).keys().get(0);
        String jwtString = Jwt.upn("jdoe@example.com")
                .jwe().keyAlgorithm(KeyEncryptionAlgorithm.RSA_OAEP)
                .encrypt(jwk.publicKey());

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
            KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("X25519");
            KeyPair kp = kpg.generateKeyPair();
            String jwtString = Jwt.upn("jdoe@example.com").jwe().encrypt(kp.getPublic());
            JsonWebToken jwt = new DefaultJWTParser().decrypt(jwtString, kp.getPrivate());
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
        config.setSignatureAlgorithm(Set.of(SignatureAlgorithm.HS256));
        JsonWebToken jwt = new DefaultJWTParser().parse(jwtString, config);
        assertEquals("jdoe@example.com", jwt.getName());
    }

    private static SecretKey createSecretKey() throws Exception {
        String jwkJson = "{\"kty\":\"oct\",\"k\":\"Fdh9u8rINxfivbrianbbVT1u232VQBZYKx1HGAGPt2I\"}";
        OctetSequenceKey jwk = OctetSequenceKey.parse(jwkJson);
        return jwk.toSecretKey("AES");
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
                "ParseException is expected");
        assertTrue(thrown.getCause() instanceof TokenExpiredException);
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
                "ParseException is expected");
        assertTrue(thrown.getCause() instanceof TokenExpiredException);
    }

    @Test
    void parseSignatureAlgorithmNotAllowed() throws Exception {
        // the token is signed with RS256 but only ES256 is accepted
        String jwtString = Jwt.upn("jdoe@example.com").issuer("https://server.example.com")
                .sign(KeyUtils.readPrivateKey("/privateKey.pem"));
        JWTAuthContextInfo config = new JWTAuthContextInfo("/publicKey.pem", "https://server.example.com");
        config.setSignatureAlgorithm(Set.of(SignatureAlgorithm.ES256));

        ParseException thrown = assertThrows(ParseException.class, () -> new DefaultJWTParser().parse(jwtString, config));
        assertTrue(thrown.getCause() instanceof InvalidJWTException);
        assertTrue(thrown.getCause().getMessage().contains("Algorithm RS256 is not allowed"),
                thrown.getCause().getMessage());
    }

    @Test
    void parseTokenWithNoneAlgorithm() throws Exception {
        String jwtString = new PlainJWT(JWTClaimsSet.parse(claimsJson())).serialize();
        JWTAuthContextInfo config = new JWTAuthContextInfo("/publicKey.pem", "https://server.example.com");

        ParseException thrown = assertThrows(ParseException.class, () -> new DefaultJWTParser().parse(jwtString, config));
        assertTrue(thrown.getCause() instanceof InvalidJWTException);
    }

    @Test
    void parseHmacTokenSignedWithRsaPublicKey() throws Exception {
        // algorithm confusion: an HS256 token signed with the RSA public key bytes as the HMAC secret
        PublicKey publicKey = KeyUtils.readPublicKey("/publicKey.pem");
        JWSObject jws = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload(claimsJson()));
        jws.sign(new MACSigner(publicKey.getEncoded()));
        String jwtString = jws.serialize();
        JWTAuthContextInfo config = new JWTAuthContextInfo("/publicKey.pem", "https://server.example.com");

        // HS256 is not accepted by default
        ParseException thrown = assertThrows(ParseException.class, () -> new DefaultJWTParser().parse(jwtString, config));
        assertTrue(thrown.getCause().getMessage().contains("Algorithm HS256 is not allowed"),
                thrown.getCause().getMessage());

        // and even if it is, the RSA public key can not be used as an HMAC secret; the key is passed directly
        // since the key location resolver does not load a public key when HS256 is accepted
        JWTAuthContextInfo keyConfig = new JWTAuthContextInfo(publicKey, "https://server.example.com");
        keyConfig.setSignatureAlgorithm(Set.of(SignatureAlgorithm.RS256, SignatureAlgorithm.HS256));
        thrown = assertThrows(ParseException.class, () -> new DefaultJWTParser().parse(jwtString, keyConfig));
        assertTrue(thrown.getCause().getMessage().contains("Algorithm HS256 can not be used with the RSA verification key"),
                thrown.getCause().getMessage());
    }

    @Test
    void parseEncryptedTokenKeyAlgorithmNotAllowed() throws Exception {
        // the token is encrypted with RSA-OAEP but only RSA-OAEP-256 is accepted, it must be rejected before the
        // inner signed token is checked
        String jwtString = Jwt.upn("jdoe@example.com").issuer("https://server.example.com")
                .innerSign(KeyUtils.readPrivateKey("/privateKey.pem"))
                .encrypt(KeyUtils.readEncryptionPublicKey("/publicKey.pem"));
        JWTAuthContextInfo config = new JWTAuthContextInfo("/publicKey.pem", "https://server.example.com");
        config.setDecryptionKeyLocation("/privateKey.pem");
        config.setKeyEncryptionAlgorithm(Set.of(KeyEncryptionAlgorithm.RSA_OAEP_256));

        ParseException thrown = assertThrows(ParseException.class, () -> new DefaultJWTParser().parse(jwtString, config));
        assertTrue(thrown.getMessage().contains("SRJWT07013"), thrown.getMessage());
        assertTrue(thrown.getCause().getMessage().contains("Key encryption algorithm RSA-OAEP is not allowed"),
                thrown.getCause().getMessage());
    }

    @Test
    void parseEncryptedTokenInnerSignatureAlgorithmNotAllowed() throws Exception {
        // the inner token is signed with ES256 but only RS256 is accepted by default
        String jwtString = Jwt.upn("jdoe@example.com").issuer("https://server.example.com")
                .jws().algorithm(SignatureAlgorithm.ES256)
                .innerSign(KeyUtils.readPrivateKey("/ecPrivateKey.pem", SignatureAlgorithm.ES256))
                .encrypt(KeyUtils.readEncryptionPublicKey("/publicKey.pem"));
        JWTAuthContextInfo config = new JWTAuthContextInfo("/publicKey.pem", "https://server.example.com");
        config.setDecryptionKeyLocation("/privateKey.pem");

        ParseException thrown = assertThrows(ParseException.class, () -> new DefaultJWTParser().parse(jwtString, config));
        assertTrue(thrown.getCause().getMessage().contains("Algorithm ES256 is not allowed"),
                thrown.getCause().getMessage());
    }

    @Test
    void parseEncryptedOnlyTokenKeyAlgorithmNotAllowed() throws Exception {
        // the token is encrypted with RSA-OAEP-256 but only RSA-OAEP is accepted
        String jwtString = Jwt.upn("jdoe@example.com")
                .jwe().keyAlgorithm(KeyEncryptionAlgorithm.RSA_OAEP_256)
                .encrypt(KeyUtils.readEncryptionPublicKey("/publicKey.pem"));
        JWTAuthContextInfo config = new JWTAuthContextInfo();
        config.setDecryptionKeyLocation("/privateKey.pem");
        config.setKeyEncryptionAlgorithm(Set.of(KeyEncryptionAlgorithm.RSA_OAEP));

        ParseException thrown = assertThrows(ParseException.class, () -> new DefaultJWTParser().parse(jwtString, config));
        assertTrue(thrown.getCause().getMessage().contains("Key encryption algorithm RSA-OAEP-256 is not allowed"),
                thrown.getCause().getMessage());
    }

    private static String claimsJson() {
        long now = System.currentTimeMillis() / 1000;
        return "{\"iss\":\"https://server.example.com\",\"sub\":\"jdoe@example.com\",\"iat\":" + now + ",\"exp\":"
                + (now + 300) + "}";
    }
}
