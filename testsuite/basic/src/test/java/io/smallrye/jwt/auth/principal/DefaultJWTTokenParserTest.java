package io.smallrye.jwt.auth.principal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtContext;
import org.junit.Before;
import org.junit.Test;

import io.smallrye.jwt.KeyUtils;

public class DefaultJWTTokenParserTest {

    private static final String TCK_TOKEN1_AUD = "s6BhdRkqt3";

    RSAPublicKey publicKey;
    DefaultJWTTokenParser parser;
    JWTAuthContextInfo config;

    @Before
    public void setUp() throws Exception {
        publicKey = (RSAPublicKey) TokenUtils.readPublicKey("/publicKey.pem");
        parser = new DefaultJWTTokenParser();
        config = new JWTAuthContextInfo(publicKey, "https://server.example.com");
    }

    @Test
    public void testParse() throws Exception {
        JwtContext context = parser.parse(TokenUtils.signClaims("/Token1.json"), config);
        assertNotNull(context);
    }

    @Test
    public void testParseJwtSignedWith1024RsaKeyLengthAllowed() throws Exception {
        KeyPair pair = KeyUtils.generateKeyPair(1024);
        String jwt = TokenUtils.generateTokenString(pair.getPrivate(), "kid", "/Token1.json", null, null);
        JWTAuthContextInfo context = new JWTAuthContextInfo((RSAPublicKey) pair.getPublic(), "https://server.example.com");
        context.setRelaxVerificationKeyValidation(true);
        assertNotNull(parser.parse(jwt, context).getJwtClaims());
    }

    @Test
    public void testParseJwtSignedWith1024RsaKeyLengthDisallowed() throws Throwable {
        KeyPair pair = KeyUtils.generateKeyPair(1024);
        String jwt = TokenUtils.generateTokenString(pair.getPrivate(), "kid", "/Token1.json", null, null);
        JWTAuthContextInfo context = new JWTAuthContextInfo((RSAPublicKey) pair.getPublic(), "https://server.example.com");
        ParseException thrown = assertThrows("InvalidJwtException is expected",
                ParseException.class, () -> parser.parse(jwt, context));
        assertTrue(thrown.getCause() instanceof InvalidJwtException);
    }

    @Test
    public void testParseExpectedAudiencePresent() throws Exception {
        config.setExpectedAudience(Collections.singleton(TCK_TOKEN1_AUD));
        JwtContext context = parser.parse(TokenUtils.signClaims("/Token1.json"), config);
        assertNotNull(context);
    }

    @Test(expected = ParseException.class)
    public void testParseExpectedAudienceMissing() throws Exception {
        config.setExpectedAudience(Collections.singleton("MISSING"));
        parser.parse(TokenUtils.signClaims("/Token1.json"), config);
    }

    @Test
    public void testParseMultipleExpectedAudienceValues() throws Exception {
        config.setExpectedAudience(new HashSet<>(Arrays.asList("MISSING", TCK_TOKEN1_AUD)));
        JwtContext context = parser.parse(TokenUtils.signClaims("/Token1.json"), config);
        assertNotNull(context);
        assertEquals(TCK_TOKEN1_AUD, context.getJwtClaims().getAudience().get(0));
    }

    @Test(expected = ParseException.class)
    public void testParseMultipleMissingExpectedAudienceValues() throws Exception {
        config.setExpectedAudience(new HashSet<>(Arrays.asList("MISSING1", "MISSING2")));
        parser.parse(TokenUtils.signClaims("/Token1.json"), config);
    }

    @Test
    public void testParseMaxTimeToLiveNull() throws Exception {
        assertNull(config.getMaxTimeToLiveSecs());
        JwtContext context = parser.parse(TokenUtils.signClaims("/Token1.json"), config);
        assertNotNull(context);
    }

    @Test
    public void testParseMaxTimeToLiveGreaterThanExpAge() throws Exception {
        config.setMaxTimeToLiveSecs(Long.valueOf(301));
        JwtContext context = parser.parse(TokenUtils.signClaims("/Token1.json"), config);
        assertNotNull(context);
    }

    @Test
    public void testParseMaxTimeToLiveEqualToExpAge() throws Exception {
        config.setMaxTimeToLiveSecs(Long.valueOf(300));
        JwtContext context = parser.parse(TokenUtils.signClaims("/Token1.json"), config);
        assertNotNull(context);
    }

    @Test(expected = ParseException.class)
    public void testParseMaxTimeToLiveLessThanExpAge() throws Exception {
        config.setMaxTimeToLiveSecs(Long.valueOf(299));
        parser.parse(TokenUtils.signClaims("/Token1.json"), config);
    }
}
