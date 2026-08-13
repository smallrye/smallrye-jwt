package io.smallrye.jwt.common;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Date;

import org.junit.Test;

import com.nimbusds.jwt.JWTClaimsSet;

public class JwtClaimsTest {

    @Test
    public void dateClaimsAreNormalizedToEpochSeconds() {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("alice")
                .issueTime(new Date(1_000_000L * 1000))
                .notBeforeTime(new Date(1_000_100L * 1000))
                .expirationTime(new Date(1_000_300L * 1000))
                .build();
        assertTrue(claimsSet.getClaims().get("exp") instanceof Date);

        JwtClaims claims = new JwtClaims(claimsSet.getClaims());

        assertEquals(1_000_000L, claims.getClaim("iat"));
        assertEquals(1_000_100L, claims.getClaim("nbf"));
        assertEquals(1_000_300L, claims.getClaim("exp"));
        assertEquals(Long.valueOf(1_000_000L), claims.getIssuedAt());
        assertEquals(Long.valueOf(1_000_100L), claims.getNotBefore());
        assertEquals(Long.valueOf(1_000_300L), claims.getExpirationTime());
    }
}
