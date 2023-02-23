package io.smallrye.jwt;

import static java.util.stream.Collectors.toSet;
import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_ISSUER;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.stream.Stream;

import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.junit.jupiter.api.Test;

import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipalFactory;
import io.smallrye.jwt.auth.principal.ParseException;

class TestTokenRequiredClaims {
    @Test
    void base() throws Exception {
        String token = TokenUtils.signClaims("/Token1.json");
        RSAPublicKey publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, TEST_ISSUER);
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        factory.parse(token, contextInfo);
    }

    @Test
    void missingRequiredClaim() throws Exception {
        String token = TokenUtils.signClaims("/Token1.json");
        RSAPublicKey publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, TEST_ISSUER);
        contextInfo.setRequiredClaims(Collections.singleton("something"));
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();

        final ParseException exception = assertThrows(ParseException.class, () -> factory.parse(token, contextInfo));
        assertTrue(exception.getCause() instanceof InvalidJwtException);
    }

    @Test
    void missingRequiredClaims() throws Exception {
        String token = TokenUtils.signClaims("/Token1.json");
        RSAPublicKey publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, TEST_ISSUER);
        contextInfo.setRequiredClaims(Stream.of("something", "else").collect(toSet()));
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();

        final ParseException exception = assertThrows(ParseException.class, () -> factory.parse(token, contextInfo));
        assertTrue(exception.getCause() instanceof InvalidJwtException);
    }

    @Test
    void requiredClaims() throws Exception {
        String token = TokenUtils.signClaims("/Token1.json");
        RSAPublicKey publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, TEST_ISSUER);
        contextInfo.setRequiredClaims(Stream.of("roles", "customObject", "customDoubleArray").collect(toSet()));
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        factory.parse(token, contextInfo);
    }

    @Test
    void requiredAndMissingClaims() throws Exception {
        String token = TokenUtils.signClaims("/Token1.json");
        RSAPublicKey publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, TEST_ISSUER);
        contextInfo.setRequiredClaims(
                Stream.of("roles", "customObject", "customDoubleArray", "something").collect(toSet()));
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();

        final ParseException exception = assertThrows(ParseException.class, () -> factory.parse(token, contextInfo));
        assertTrue(exception.getCause() instanceof InvalidJwtException);
    }
}
