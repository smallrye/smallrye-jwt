package io.smallrye.jwt;

import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_ISSUER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.eclipse.microprofile.jwt.tck.util.SignatureAlgorithm;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipalFactory;

class TestTokenWithSubPath {
    private static String token;
    private static PublicKey publicKey;

    @BeforeAll
    static void generateToken() throws Exception {
        Map<String, Long> timeClaims = new HashMap<>();
        token = TokenUtils.signClaims("/TokenSubPath.json", SignatureAlgorithm.RS256, null, timeClaims);
        publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        if (publicKey == null) {
            throw new IllegalStateException("Failed to load /publicKey.pem resource");
        }
    }

    @Test
    void subClaimIsAvailableOnPath() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, TEST_ISSUER);
        contextInfo.setSubjectPath("realm/access/sub/principal");
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        String sub = jwt.getSubject();
        assertEquals(sub, "microprofile_jwt_principal");
    }

    @Test
    void subClaimIsAvailableOnPathWithNamespace() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, TEST_ISSUER);
        contextInfo.setSubjectPath("realm/\"https://idp/access\"/sub/principal");
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        String sub = jwt.getSubject();
        assertEquals(sub, "namespace_microprofile_jwt_principal");
    }

    @Test
    void subClaimIsNotAvailableOnTooDeepPath() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, TEST_ISSUER);
        contextInfo.setRequireNamedPrincipal(false);
        contextInfo.setSubjectPath("realm/access/sub/principal/5");
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        assertNull(jwt.getSubject());
    }

    @Test
    void subClaimIsNotAvailableIfClaimIsNotString() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, TEST_ISSUER);
        contextInfo.setRequireNamedPrincipal(false);
        contextInfo.setSubjectPath("realm/access/sub");
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        assertNull(jwt.getSubject());
    }

    @Test
    void subClaimIsNotAvailableOnWrongPath() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo(publicKey, TEST_ISSUER);
        contextInfo.setRequireNamedPrincipal(false);
        contextInfo.setSubjectPath("realm/access/user/principal");
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        assertNull(jwt.getSubject());
    }
}
