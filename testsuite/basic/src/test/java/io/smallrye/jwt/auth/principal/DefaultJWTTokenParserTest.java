package io.smallrye.jwt.auth.principal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;

import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.auth.InvalidJWTException;
import io.smallrye.jwt.auth.JwtContext;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.common.JwtClaims;
import io.smallrye.jwt.config.JWTAuthContextInfoProvider;
import io.smallrye.jwt.util.KeyUtils;
import io.smallrye.jwt.util.ResourceUtils;

class DefaultJWTTokenParserTest {

    private static final String TOKEN_NO_ISSUED_AT = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
            + ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
            + ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String ENCODED_SECRET_KEY = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
    private static final String TCK_TOKEN1_AUD = "s6BhdRkqt3";

    RSAPublicKey publicKey;
    DefaultJWTTokenParser parser;
    JWTAuthContextInfo config;

    @BeforeEach
    void setUp() throws Exception {
        publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        parser = new DefaultJWTTokenParser();
        config = new JWTAuthContextInfo(publicKey, "https://server.example.com");
    }

    @Test
    void parse() throws Exception {
        JwtContext context = parser.parse(TokenUtils.signClaims("/Token1.json"), config);
        assertNotNull(context);
    }

    @Test
    void parseJwtSignedWith1024RsaKeyLengthAllowed() throws Exception {
        KeyPair pair = KeyUtils.generateKeyPair(1024);
        String jwt = TokenUtils.generateTokenString(pair.getPrivate(), "kid", "/Token1.json", null, null);
        JWTAuthContextInfo context = new JWTAuthContextInfo(pair.getPublic(), "https://server.example.com");
        assertNotNull(parser.parse(jwt, context).claims());
    }

    @Test
    void parseJwtSignedWith1024RsaKeyLengthDisallowed() throws Throwable {
        KeyPair pair = KeyUtils.generateKeyPair(1024);
        String jwt = TokenUtils.generateTokenString(pair.getPrivate(), "kid", "/Token1.json", null, null);
        JWTAuthContextInfo context = new JWTAuthContextInfo(pair.getPublic(), "https://server.example.com");
        context.setRelaxVerificationKeyValidation(false);
        ParseException thrown = assertThrows(ParseException.class, () -> parser.parse(jwt, context),
                "InvalidJWTException is expected");
        assertTrue(thrown.getCause() instanceof InvalidJWTException);
    }

    @Test
    void parseExpectedAudiencePresent() throws Exception {
        config.setExpectedAudience(Collections.singleton(TCK_TOKEN1_AUD));
        JwtContext context = parser.parse(TokenUtils.signClaims("/Token1.json"), config);
        assertNotNull(context);
    }

    @Test
    void parseExpectedAudienceMissing() throws Exception {
        config.setExpectedAudience(Collections.singleton("MISSING"));
        assertThrows(ParseException.class, () -> parser.parse(TokenUtils.signClaims("/Token1.json"), config));
    }

    @Test
    @SuppressWarnings("unchecked")
    void parseMultipleExpectedAudienceValues() throws Exception {
        config.setExpectedAudience(new HashSet<>(Arrays.asList("MISSING", TCK_TOKEN1_AUD)));
        JwtContext context = parser.parse(TokenUtils.signClaims("/Token1.json"), config);
        assertNotNull(context);
        List<String> audience = (List<String>) context.claims().getClaim("aud");
        assertEquals(TCK_TOKEN1_AUD, audience.get(0));
    }

    @Test
    void parseMultipleMissingExpectedAudienceValues() throws Exception {
        config.setExpectedAudience(new HashSet<>(Arrays.asList("MISSING1", "MISSING2")));
        assertThrows(ParseException.class, () -> parser.parse(TokenUtils.signClaims("/Token1.json"), config));
    }

    @Test
    void parseMaxTimeToLiveNull() throws Exception {
        assertNull(config.getMaxTimeToLiveSecs());
        JwtContext context = parser.parse(TokenUtils.signClaims("/Token1.json"), config);
        assertNotNull(context);
    }

    @Test
    void tokenNoIssuedAtFailed() throws Throwable {
        JWTAuthContextInfo context = new JWTAuthContextInfo();
        context.setIssuedBy("joe");
        context.setSignatureAlgorithm(Set.of(SignatureAlgorithm.HS256));
        context.setSecretVerificationKey(KeyUtils.createSecretKeyFromEncodedSecret(ENCODED_SECRET_KEY));
        context.setExpGracePeriodSecs(Integer.MAX_VALUE);
        context.setDefaultSubjectClaim("iss");

        ParseException thrown = assertThrows(ParseException.class, () -> parser.parse(TOKEN_NO_ISSUED_AT, context),
                "InvalidJWTException is expected");
        assertTrue(thrown.getCause() instanceof InvalidJWTException);
    }

    @Test
    void tokenNoIssuedAtAllowed() throws Throwable {
        JWTAuthContextInfo context = new JWTAuthContextInfo();
        context.setIssuedBy("joe");
        context.setSignatureAlgorithm(Set.of(SignatureAlgorithm.HS256));
        context.setSecretVerificationKey(KeyUtils.createSecretKeyFromEncodedSecret(ENCODED_SECRET_KEY));
        context.setMaxTimeToLiveSecs(0L);
        context.setExpGracePeriodSecs(Integer.MAX_VALUE);
        context.setDefaultSubjectClaim("iss");

        JwtClaims claims = parser.parse(TOKEN_NO_ISSUED_AT, context).claims();
        assertEquals("joe", claims.getClaim("iss"));
        assertNotNull(claims.getClaim("exp"));
        assertTrue((Boolean) claims.getClaim("http://example.com/is_root"));

    }

    @Test
    void tokenNumericSubjectFailed() throws Throwable {
        JWTAuthContextInfo context = new JWTAuthContextInfo();
        context.setIssuedBy("joe");
        context.setSignatureAlgorithm(Set.of(SignatureAlgorithm.HS256));
        context.setSecretVerificationKey(KeyUtils.createSecretKeyFromEncodedSecret(ENCODED_SECRET_KEY));

        // 'sub' must be a string, a number is rejected as jose4j did; the build API refuses to
        // create such a token, so sign the raw payload directly
        long now = System.currentTimeMillis() / 1000;
        JWSObject jws = new JWSObject(new JWSHeader(JWSAlgorithm.HS256),
                new Payload("{\"iss\":\"joe\",\"sub\":123,\"iat\":" + now + ",\"exp\":" + (now + 300) + "}"));
        jws.sign(new MACSigner(KeyUtils.createSecretKeyFromEncodedSecret(ENCODED_SECRET_KEY)));
        String token = jws.serialize();

        ParseException thrown = assertThrows(ParseException.class, () -> parser.parse(token, context),
                "ParseException is expected");
        assertTrue(thrown.getCause().getMessage().contains("\"sub\" claim must be a string"),
                thrown.getCause().getMessage());
    }

    @Test
    void tokenExpirationOutOfRangeFailed() throws Throwable {
        JWTAuthContextInfo context = new JWTAuthContextInfo();
        context.setIssuedBy("joe");
        context.setSignatureAlgorithm(Set.of(SignatureAlgorithm.HS256));
        context.setSecretVerificationKey(KeyUtils.createSecretKeyFromEncodedSecret(ENCODED_SECRET_KEY));

        // Instant.MIN epoch seconds overflow when Nimbus converts them to milliseconds, which would make
        // this long expired token look like a valid token
        long now = System.currentTimeMillis() / 1000;
        JWSObject jws = new JWSObject(new JWSHeader(JWSAlgorithm.HS256),
                new Payload("{\"iss\":\"joe\",\"sub\":\"joe\",\"iat\":" + now + ",\"exp\":"
                        + Instant.MIN.getEpochSecond() + "}"));
        jws.sign(new MACSigner(KeyUtils.createSecretKeyFromEncodedSecret(ENCODED_SECRET_KEY)));
        String token = jws.serialize();

        ParseException thrown = assertThrows(ParseException.class, () -> parser.parse(token, context),
                "ParseException is expected");
        assertTrue(thrown.getCause().getMessage().contains("\"exp\" claim value is out of range"),
                thrown.getCause().getMessage());
    }

    @Test
    void tokenIssuedAtAfterExpirationFailed() throws Throwable {
        JWTAuthContextInfo context = new JWTAuthContextInfo();
        context.setIssuedBy("joe");
        context.setSignatureAlgorithm(Set.of(SignatureAlgorithm.HS256));
        context.setSecretVerificationKey(KeyUtils.createSecretKeyFromEncodedSecret(ENCODED_SECRET_KEY));
        // 'iat' is optional, as in tokenNoIssuedAtAllowed, but it must still not be after 'exp'
        context.setMaxTimeToLiveSecs(0L);
        context.setDefaultSubjectClaim("iss");

        long now = System.currentTimeMillis() / 1000;
        String token = Jwt.issuer("joe").issuedAt(now + 200).expiresAt(now + 100)
                .sign(KeyUtils.createSecretKeyFromEncodedSecret(ENCODED_SECRET_KEY));

        ParseException thrown = assertThrows(ParseException.class, () -> parser.parse(token, context),
                "ParseException is expected");
        assertTrue(thrown.getCause().getMessage().contains("SRJWT07015"), thrown.getCause().getMessage());
    }

    @Test
    void parseMaxTimeToLiveGreaterThanExpAge() throws Exception {
        config.setMaxTimeToLiveSecs(301L);
        JwtContext context = parser.parse(TokenUtils.signClaims("/Token1.json"), config);
        assertNotNull(context);
    }

    @Test
    void parseMaxTimeToLiveEqualToExpAge() throws Exception {
        config.setMaxTimeToLiveSecs(300L);
        JwtContext context = parser.parse(TokenUtils.signClaims("/Token1.json"), config);
        assertNotNull(context);
    }

    @Test
    void parseMaxTimeToLiveLessThanExpAge() {
        config.setMaxTimeToLiveSecs(299L);
        assertThrows(ParseException.class, () -> parser.parse(TokenUtils.signClaims("/Token1.json"), config));
    }

    @Test
    void verifyTokenWithThumbprint() throws Exception {
        X509Certificate cert = KeyUtils.getCertificate(ResourceUtils.readResource("/certificate.pem"));
        String jwtString = Jwt.upn("Alice").issuer("https://server.example.com")
                .jws().thumbprint(cert)
                .sign(KeyUtils.readPrivateKey("/privateKey2.pem"));
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider.createWithCertificate("/certificate.pem",
                "https://server.example.com");
        JwtClaims claims = new DefaultJWTTokenParser().parse(jwtString, provider.getContextInfo()).claims();
        assertEquals("Alice", claims.getClaim("upn"));
    }

    @Test
    void verifyTokenWithoutThumbprint() throws Exception {
        String jwtString = Jwt.upn("Alice").issuer("https://server.example.com")
                .sign(KeyUtils.readPrivateKey("/privateKey2.pem"));
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider.createWithCertificate("/certificate.pem",
                "https://server.example.com");
        assertThrows(ParseException.class, () -> new DefaultJWTTokenParser().parse(jwtString, provider.getContextInfo()));
    }
}
