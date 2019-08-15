package io.smallrye.jwt.auth.principal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.jose4j.jwt.consumer.JwtContext;
import org.junit.Before;
import org.junit.Test;

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
        JwtContext context = parser.parse(TokenUtils.generateTokenString("/Token1.json"), config);
        assertNotNull(context);
    }

    @Test
    public void testParseExpectedAudiencePresent() throws Exception {
        config.setExpectedAudience(Collections.singleton(TCK_TOKEN1_AUD));
        JwtContext context = parser.parse(TokenUtils.generateTokenString("/Token1.json"), config);
        assertNotNull(context);
    }

    @Test(expected = ParseException.class)
    public void testParseExpectedAudienceMissing() throws Exception {
        config.setExpectedAudience(Collections.singleton("MISSING"));
        parser.parse(TokenUtils.generateTokenString("/Token1.json"), config);
    }

    @Test
    public void testParseMultipleExpectedAudienceValues() throws Exception {
        config.setExpectedAudience(new HashSet<>(Arrays.asList("MISSING", TCK_TOKEN1_AUD)));
        JwtContext context = parser.parse(TokenUtils.generateTokenString("/Token1.json"), config);
        assertNotNull(context);
        assertEquals(TCK_TOKEN1_AUD, context.getJwtClaims().getAudience().get(0));
    }

    @Test(expected = ParseException.class)
    public void testParseMultipleMissingExpectedAudienceValues() throws Exception {
        config.setExpectedAudience(new HashSet<>(Arrays.asList("MISSING1", "MISSING2")));
        parser.parse(TokenUtils.generateTokenString("/Token1.json"), config);
    }
}
