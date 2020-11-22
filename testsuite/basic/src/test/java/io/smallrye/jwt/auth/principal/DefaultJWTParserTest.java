package io.smallrye.jwt.auth.principal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.junit.Test;

import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.util.KeyUtils;
import io.smallrye.jwt.util.ResourceUtils;

public class DefaultJWTParserTest {

    @Test
    public void testParseWithConfiguredPublicKey() throws Exception {
        String jwtString = Jwt.upn("jdoe@example.com").issuer("https://server.example.com")
                .sign(KeyUtils.readPrivateKey("/privateKey.pem"));
        JWTAuthContextInfo config = new JWTAuthContextInfo("/publicKey.pem", "https://server.example.com");
        JWTParser parser = new DefaultJWTParser(config);
        JsonWebToken jwt = parser.parse(jwtString);
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    public void testParseWithConfiguredCert() throws Exception {
        String jwtString = Jwt.upn("jdoe@example.com").issuer("https://server.example.com")
                .sign(KeyUtils.readPrivateKey("/privateKey2.pem"));
        JWTAuthContextInfo config = new JWTAuthContextInfo("/certificate.pem", "https://server.example.com");
        JWTParser parser = new DefaultJWTParser(config);
        JsonWebToken jwt = parser.parse(jwtString);
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    public void testParseWithConfiguredCertAndThumbprint() throws Exception {
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
    public void testParseWithConfiguredCertAndThumbprintS256() throws Exception {
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
    public void testParseWithConfiguredCertAndThumbprintMissing() throws Exception {
        String jwtString = Jwt.upn("jdoe@example.com").issuer("https://server.example.com")
                .sign(KeyUtils.readPrivateKey("/privateKey2.pem"));
        JWTAuthContextInfo config = new JWTAuthContextInfo("/certificate.pem", "https://server.example.com");
        config.setVerifyCertificateThumbprint(true);
        JWTParser parser = new DefaultJWTParser(config);
        ParseException thrown = assertThrows("InvalidJwtException is expected",
                ParseException.class, () -> parser.parse(jwtString));
        assertTrue(thrown.getCause() instanceof InvalidJwtException);
    }

    @Test
    public void testParseWithCustomContext() throws Exception {
        String jwtString = Jwt.upn("jdoe@example.com").issuer("https://server.example.com")
                .sign(KeyUtils.readPrivateKey("/privateKey.pem"));
        JWTAuthContextInfo config = new JWTAuthContextInfo("/publicKey.pem", "https://server.example.com");
        JsonWebToken jwt = new DefaultJWTParser().parse(jwtString, config);
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    public void testVerifyWithRsaPublicKey() throws Exception {
        String jwtString = Jwt.upn("jdoe@example.com").sign(KeyUtils.readPrivateKey("/privateKey.pem"));
        JsonWebToken jwt = new DefaultJWTParser().verify(jwtString, KeyUtils.readPublicKey("/publicKey.pem"));
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    public void testVerifyWithEcPublicKey() throws Exception {
        String jwtString = Jwt.upn("jdoe@example.com").sign(
                KeyUtils.readPrivateKey("/ecPrivateKey.pem", SignatureAlgorithm.ES256));
        JsonWebToken jwt = new DefaultJWTParser().verify(jwtString,
                KeyUtils.readPublicKey("/ecPublicKey.pem", SignatureAlgorithm.ES256));
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    public void testVerifyWithSecretKey() throws Exception {
        SecretKey secretKey = createSecretKey();
        String jwtString = Jwt.upn("jdoe@example.com").sign(secretKey);
        JsonWebToken jwt = new DefaultJWTParser().verify(jwtString, secretKey);
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    public void testVerifyWithSecretString() throws Exception {
        String secret = "AyM1SysPpbyDfgZld3umj1qzKObwVMko";
        String jwtString = Jwt.upn("jdoe@example.com").signWithSecret(secret);
        JsonWebToken jwt = new DefaultJWTParser().verify(jwtString, secret);
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    public void testDecryptWithRsaPrivateKey() throws Exception {
        String jwtString = Jwt.upn("jdoe@example.com")
                .jwe().keyAlgorithm(KeyEncryptionAlgorithm.RSA_OAEP)
                .encrypt(KeyUtils.readEncryptionPublicKey("/publicKey.pem"));
        JsonWebToken jwt = new DefaultJWTParser().decrypt(jwtString, KeyUtils.readDecryptionPrivateKey("/privateKey.pem"));
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    public void testDecryptWithRsaPrivateKeyInJwkFormat() throws Exception {
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
    public void testDecryptWithEcPrivateKey() throws Exception {
        String jwtString = Jwt.upn("jdoe@example.com").jwe().encrypt(
                KeyUtils.readEncryptionPublicKey("/ecPublicKey.pem", KeyEncryptionAlgorithm.ECDH_ES_A256KW));
        JsonWebToken jwt = new DefaultJWTParser().decrypt(jwtString,
                KeyUtils.readDecryptionPrivateKey("/ecPrivateKey.pem", KeyEncryptionAlgorithm.ECDH_ES_A256KW));
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    public void testDecryptWithSecretKey() throws Exception {
        SecretKey secretKey = createSecretKey();
        String jwtString = Jwt.upn("jdoe@example.com").jwe().encrypt(secretKey);
        JsonWebToken jwt = new DefaultJWTParser().decrypt(jwtString, secretKey);
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    public void testDecryptWithSecretString() throws Exception {
        String secret = "AyM1SysPpbyDfgZld3umj1qzKObwVMko";
        String jwtString = Jwt.upn("jdoe@example.com").jwe().encryptWithSecret(secret);
        JsonWebToken jwt = new DefaultJWTParser().decrypt(jwtString, secret);
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    public void testDecryptVerifyWithSecretKey() throws Exception {
        SecretKey secretKey = createSecretKey();
        String jwtString = Jwt.upn("jdoe@example.com")
                .innerSign(secretKey)
                .encrypt(secretKey);
        JWTAuthContextInfo config = new JWTAuthContextInfo();
        config.setSecretDecryptionKey(secretKey);
        config.setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm.A256KW);
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

}
