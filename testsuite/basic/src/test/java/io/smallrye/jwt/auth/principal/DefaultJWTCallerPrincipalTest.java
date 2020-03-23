package io.smallrye.jwt.auth.principal;

import static org.junit.Assert.*;

import java.security.interfaces.RSAPublicKey;
import java.util.Set;

import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.jose4j.jwt.consumer.JwtContext;
import org.junit.Before;
import org.junit.Test;

public class DefaultJWTCallerPrincipalTest {

    private static final String TCK_TOKEN1_AUD = "s6BhdRkqt3";

    RSAPublicKey publicKey;
    DefaultJWTTokenParser parser;
    JWTAuthContextInfo config;
    JwtContext context;

    @Before
    public void setUp() throws Exception {
        publicKey = (RSAPublicKey) TokenUtils.readPublicKey("/publicKey.pem");
        parser = new DefaultJWTTokenParser();
        config = new JWTAuthContextInfo(publicKey, "https://server.example.com");
        context = parser.parse(TokenUtils.signClaims("/Token1.json"), config);
    }

    @Test
    public void testGetAudience() {
        DefaultJWTCallerPrincipal principal = new DefaultJWTCallerPrincipal(context.getJwtClaims());
        Set<String> audience = principal.getAudience();
        assertNotNull(audience);
        assertEquals(1, audience.size());
        assertArrayEquals(new String[] { TCK_TOKEN1_AUD }, audience.toArray(new String[0]));
    }

    @Test
    public void testGetAudienceClaimValue() {
        DefaultJWTCallerPrincipal principal = new DefaultJWTCallerPrincipal(context.getJwtClaims());
        @SuppressWarnings("unchecked")
        Set<String> audience = (Set<String>) principal.getClaimValue(Claims.aud.name());
        assertNotNull(audience);
        assertEquals(1, audience.size());
        assertArrayEquals(new String[] { TCK_TOKEN1_AUD }, audience.toArray(new String[0]));
    }

    @Test
    public void testGetAudienceClaim() {
        DefaultJWTCallerPrincipal principal = new DefaultJWTCallerPrincipal(context.getJwtClaims());
        Set<String> audience = principal.getClaim(Claims.aud.name());
        assertNotNull(audience);
        assertEquals(1, audience.size());
        assertArrayEquals(new String[] { TCK_TOKEN1_AUD }, audience.toArray(new String[0]));
    }

}
