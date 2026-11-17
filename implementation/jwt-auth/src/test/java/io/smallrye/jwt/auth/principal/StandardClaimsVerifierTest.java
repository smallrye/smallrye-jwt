package io.smallrye.jwt.auth.principal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.text.ParseException;
import java.util.Date;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.nimbusds.jwt.JWTClaimsSet;

import io.smallrye.jwt.auth.InvalidJWTException;
import io.smallrye.jwt.auth.TokenExpiredException;

class StandardClaimsVerifierTest {

    private static final StandardClaimsVerifier VERIFIER = StandardClaimsVerifier.builder().build();

    @Test
    void expirationTimeBeforeIssuedAt() {
        long now = System.currentTimeMillis() / 1000;
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issueTime(new Date((now + 200) * 1000))
                .expirationTime(new Date((now + 100) * 1000))
                .build();

        InvalidJWTException thrown = assertThrows(InvalidJWTException.class, () -> VERIFIER.verify(claims));
        assertTrue(thrown.getMessage().contains("SRJWT07015"), thrown.getMessage());
    }

    @Test
    void expirationTimeBeforeNotBefore() {
        long now = System.currentTimeMillis() / 1000;
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .notBeforeTime(new Date((now - 100) * 1000))
                .expirationTime(new Date((now - 200) * 1000))
                .build();

        // the token is also expired, which takes precedence as in jose4j
        assertThrows(TokenExpiredException.class, () -> VERIFIER.verify(claims));

        // 'exp' before 'nbf' can only pass the expiry and not-before checks within the clock skew window
        StandardClaimsVerifier skewVerifier = StandardClaimsVerifier.builder().clockSkewSeconds(60).build();
        JWTClaimsSet skewClaims = new JWTClaimsSet.Builder()
                .notBeforeTime(new Date((now + 30) * 1000))
                .expirationTime(new Date((now - 30) * 1000))
                .build();
        InvalidJWTException thrown = assertThrows(InvalidJWTException.class, () -> skewVerifier.verify(skewClaims));
        assertTrue(thrown.getMessage().contains("SRJWT07024"), thrown.getMessage());
    }

    @Test
    void requiredClaimWithNullValueIsRejected() throws Exception {
        StandardClaimsVerifier verifier = StandardClaimsVerifier.builder().requiredClaims(Set.of("exp")).build();

        // "exp": null must be treated as a missing claim, as jose4j did, otherwise the token never expires
        JWTClaimsSet claims = StandardClaimsVerifier.parseClaimsSet("{\"sub\":\"alice\",\"exp\":null}");
        InvalidJWTException thrown = assertThrows(InvalidJWTException.class, () -> verifier.verify(claims));
        assertTrue(thrown.getMessage().contains("missing required claims: [exp]"), thrown.getMessage());

        JWTClaimsSet noExp = StandardClaimsVerifier.parseClaimsSet("{\"sub\":\"alice\"}");
        thrown = assertThrows(InvalidJWTException.class, () -> verifier.verify(noExp));
        assertTrue(thrown.getMessage().contains("missing required claims: [exp]"), thrown.getMessage());
    }

    @Test
    void duplicateClaimNamesAreRejected() {
        ParseException thrown = assertThrows(ParseException.class,
                () -> StandardClaimsVerifier.parseClaimsSet("{\"sub\":\"alice\",\"sub\":\"bob\"}"));
        assertTrue(thrown.getMessage().startsWith("Invalid JWT claims"), thrown.getMessage());

        // nested duplicates are rejected as well, Nimbus alone accepts them and the last one wins
        thrown = assertThrows(ParseException.class,
                () -> StandardClaimsVerifier.parseClaimsSet("{\"address\":{\"country\":\"CZ\",\"country\":\"SK\"}}"));
        assertTrue(thrown.getMessage().startsWith("Invalid JWT claims"), thrown.getMessage());
    }

    @Test
    void integerClaimsOutsideLongRangeAreKept() throws Exception {
        // Nimbus alone converts such integers to doubles
        JWTClaimsSet claims = StandardClaimsVerifier.parseClaimsSet("{\"id\":123456789012345678901234567890}");
        assertEquals(new BigInteger("123456789012345678901234567890"), claims.getClaim("id"));

        // numeric dates outside of the long range are rejected rather than converted
        ParseException thrown = assertThrows(ParseException.class,
                () -> StandardClaimsVerifier.parseClaimsSet("{\"exp\":9223372036854775808}"));
        assertTrue(thrown.getMessage().contains("\"exp\" claim value is out of range"), thrown.getMessage());
        thrown = assertThrows(ParseException.class,
                () -> StandardClaimsVerifier.parseClaimsSet("{\"iat\":" + Long.MIN_VALUE + "}"));
        assertTrue(thrown.getMessage().contains("\"iat\" claim value is out of range"), thrown.getMessage());
        thrown = assertThrows(ParseException.class,
                () -> StandardClaimsVerifier.parseClaimsSet("{\"nbf\":1e400}"));
        assertTrue(thrown.getMessage().contains("\"nbf\" claim value is out of range"), thrown.getMessage());
    }

    @Test
    void consistentTimesAreAccepted() throws Exception {
        long now = System.currentTimeMillis() / 1000;
        VERIFIER.verify(new JWTClaimsSet.Builder()
                .issueTime(new Date((now - 10) * 1000))
                .notBeforeTime(new Date((now - 10) * 1000))
                .expirationTime(new Date((now + 100) * 1000))
                .build());
        VERIFIER.verify(new JWTClaimsSet.Builder().expirationTime(new Date((now + 100) * 1000)).build());
    }
}
