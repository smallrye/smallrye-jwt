package io.smallrye.jwt.common;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.util.Date;

import jakarta.json.JsonException;

import org.junit.Test;

import com.nimbusds.jwt.JWTClaimsSet;

public class JwtClaimsTest {

    @Test
    public void integerClaimsOutsideLongRangeAreNotTruncated() {
        JwtClaims claims = JwtClaims.parse("{\"small\":42,\"big\":123456789012345678901234567890,\"dec\":1.5}");
        assertEquals(42L, claims.getClaim("small"));
        assertEquals(new BigInteger("123456789012345678901234567890"), claims.getClaim("big"));
        assertEquals(1.5d, claims.getClaim("dec"));
        assertTrue(claims.toJsonString().contains("\"big\":123456789012345678901234567890"));
    }

    @Test
    public void duplicateClaimNamesAreRejected() {
        // RFC 7519, section 4: the claim names must be unique, as jose4j required
        assertThrows(JsonException.class, () -> JwtClaims.parse("{\"exp\":1,\"exp\":2}"));
        assertThrows(JsonException.class, () -> JwtClaims.parse("{\"address\":{\"country\":\"CZ\",\"country\":\"SK\"}}"));
        assertThrows(JsonException.class, () -> JwtClaims.parse("{\"roles\":[{\"name\":\"a\",\"name\":\"b\"}]}"));

        assertEquals("CZ", ((java.util.Map<?, ?>) JwtClaims.parse("{\"address\":{\"country\":\"CZ\"}}")
                .getClaim("address")).get("country"));
    }

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
