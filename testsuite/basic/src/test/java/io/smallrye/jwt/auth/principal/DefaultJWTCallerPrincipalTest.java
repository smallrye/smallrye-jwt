package io.smallrye.jwt.auth.principal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.interfaces.RSAPublicKey;
import java.util.Set;

import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DefaultJWTCallerPrincipalTest {

    private static final String TCK_TOKEN1_AUD = "s6BhdRkqt3";

    RSAPublicKey publicKey;
    DefaultJWTTokenParser parser;
    JWTAuthContextInfo config;
    JwtContext context;

    @BeforeEach
    void setUp() throws Exception {
        publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        parser = new DefaultJWTTokenParser();
        config = new JWTAuthContextInfo(publicKey, "https://server.example.com");
        context = parser.parse(TokenUtils.signClaims("/Token1.json"), config);
    }

    @Test
    void getAudience() {
        DefaultJWTCallerPrincipal principal = new DefaultJWTCallerPrincipal(context.getJwtClaims());
        Set<String> audience = principal.getAudience();
        assertNotNull(audience);
        assertEquals(1, audience.size());
        assertArrayEquals(new String[] { TCK_TOKEN1_AUD }, audience.toArray(new String[0]));
    }

    @Test
    void getAudienceClaimValue() {
        DefaultJWTCallerPrincipal principal = new DefaultJWTCallerPrincipal(context.getJwtClaims());
        @SuppressWarnings("unchecked")
        Set<String> audience = (Set<String>) principal.getClaimValue(Claims.aud.name());
        assertNotNull(audience);
        assertEquals(1, audience.size());
        assertArrayEquals(new String[] { TCK_TOKEN1_AUD }, audience.toArray(new String[0]));
    }

    @Test
    void getAudienceClaim() {
        DefaultJWTCallerPrincipal principal = new DefaultJWTCallerPrincipal(context.getJwtClaims());
        Set<String> audience = principal.getClaim(Claims.aud.name());
        assertNotNull(audience);
        assertEquals(1, audience.size());
        assertArrayEquals(new String[] { TCK_TOKEN1_AUD }, audience.toArray(new String[0]));
    }

    @Test
    void claimsWithDecimalValues() {
        Double exp = 1311281970.5;
        Double iat = 1311280970.5;

        final JwtClaims claims = context.getJwtClaims();
        claims.setClaim(Claims.exp.name(), exp);
        claims.setClaim(Claims.iat.name(), iat);
        DefaultJWTCallerPrincipal principal = new DefaultJWTCallerPrincipal(claims);

        Long expClaim = principal.getExpirationTime();
        Long iatClaim = principal.getIssuedAtTime();

        assertNotNull(expClaim);
        assertNotNull(iatClaim);

        assertEquals(exp.longValue(), expClaim);
        assertEquals(iat.longValue(), iatClaim);
    }
}
