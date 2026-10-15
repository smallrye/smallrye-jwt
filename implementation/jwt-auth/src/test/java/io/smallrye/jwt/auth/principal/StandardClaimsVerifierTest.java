package io.smallrye.jwt.auth.principal;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Date;

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
