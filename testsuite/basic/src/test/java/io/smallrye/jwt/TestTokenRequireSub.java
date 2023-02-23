package io.smallrye.jwt;

import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_ISSUER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.eclipse.microprofile.jwt.tck.util.SignatureAlgorithm;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.junit.jupiter.api.Test;

import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipalFactory;
import io.smallrye.jwt.auth.principal.ParseException;

class TestTokenRequireSub {
    @Test
    void defaultSubAvailable() throws Exception {
        Map<String, Long> timeClaims = new HashMap<>();
        String token = TokenUtils.signClaims("/Token1.json", SignatureAlgorithm.RS256, null, timeClaims);
        RSAPublicKey publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        if (publicKey == null) {
            throw new IllegalStateException("Failed to load /publicKey.pem resource");
        }

        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, TEST_ISSUER);
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        String sub = jwt.getSubject();
        assertEquals(sub, "24400320");
    }

    @Test
    void defaultSubNotAvailable() throws Exception {
        Map<String, Long> timeClaims = new HashMap<>();
        String token = TokenUtils.signClaims("/TokenSubPath.json", SignatureAlgorithm.RS256, null, timeClaims);
        RSAPublicKey publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        if (publicKey == null) {
            throw new IllegalStateException("Failed to load /publicKey.pem resource");
        }

        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, TEST_ISSUER);
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        assertThrows(ParseException.class, () -> factory.parse(token, contextInfo));
    }

    @Test
    void noSubValidation() throws Exception {
        Map<String, Long> timeClaims = new HashMap<>();
        String token = TokenUtils.signClaims("/TokenSubPath.json", SignatureAlgorithm.RS256, null, timeClaims);
        RSAPublicKey publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        if (publicKey == null) {
            throw new IllegalStateException("Failed to load /publicKey.pem resource");
        }

        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, TEST_ISSUER);
        contextInfo.setRequireNamedPrincipal(false);
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        String sub = jwt.getSubject();
        assertNull(sub);
    }
}
