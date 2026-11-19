package io.smallrye.jwt.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.util.Date;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.common.MalformedClaimException;
import io.smallrye.jwt.util.KeyUtils;

class JwtVerifierTest {

    @Test
    void claimsValidatorError() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair(2048);
        String token = sign(keyPair);

        JwtVerifier verifier = verifier(keyPair).claimsValidator(context -> "Invalid nonce").build();
        InvalidJWTException thrown = assertThrows(InvalidJWTException.class, () -> verifier.verify(token));
        assertEquals("Invalid nonce", thrown.getMessage());

        JwtVerifier passing = verifier(keyPair).claimsValidator(context -> null).build();
        assertEquals("alice", passing.verify(token).claims().getSubject());
    }

    @Test
    void claimsValidatorException() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair(2048);
        String token = sign(keyPair);

        // as with jose4j, a validator exception rejects the token instead of escaping the verification
        IllegalStateException failure = new IllegalStateException("boom");
        JwtVerifier verifier = verifier(keyPair).claimsValidator(context -> {
            throw failure;
        }).build();
        InvalidJWTException thrown = assertThrows(InvalidJWTException.class, () -> verifier.verify(token));
        assertTrue(thrown.getMessage().startsWith("Unexpected exception thrown from validator "), thrown.getMessage());
        assertTrue(thrown.getMessage().endsWith("java.lang.IllegalStateException: boom"), thrown.getMessage());
        assertSame(failure, thrown.getCause());
    }

    @Test
    void claimsValidatorMalformedClaim() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair(2048);
        String token = sign(keyPair);

        // the 'sub' claim is a string, requesting it as a list fails with the claim error itself, as with jose4j
        JwtVerifier verifier = verifier(keyPair).claimsValidator(context -> {
            context.claims().getStringListClaim("sub");
            return null;
        }).build();
        InvalidJWTException thrown = assertThrows(InvalidJWTException.class, () -> verifier.verify(token));
        assertEquals("The value of the 'sub' claim is not a list but java.lang.String", thrown.getMessage());
        assertTrue(thrown.getCause() instanceof MalformedClaimException);
    }

    private static JwtVerifier.Builder verifier(KeyPair keyPair) {
        return JwtVerifier.builder()
                .verificationKeyResolver(jws -> keyPair.getPublic())
                .allowedAlgorithms(Set.of(SignatureAlgorithm.RS256));
    }

    private static String sign(KeyPair keyPair) throws Exception {
        long now = System.currentTimeMillis();
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256),
                new JWTClaimsSet.Builder()
                        .subject("alice")
                        .issueTime(new Date(now))
                        .expirationTime(new Date(now + 300_000))
                        .build());
        jwt.sign(new RSASSASigner(keyPair.getPrivate()));
        return jwt.serialize();
    }
}
