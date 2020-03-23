package io.smallrye.jwt;

import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_GROUP_JWT;
import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_ISSUER;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.jboss.arquillian.testng.Arquillian;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipalFactory;

public class TestTokenWithSubPath extends Arquillian {
    private static String token;
    private static PublicKey publicKey;

    @BeforeClass(alwaysRun = true)
    public static void generateToken() throws Exception {
        Map<String, Long> timeClaims = new HashMap<>();
        token = TokenUtils.signClaims("/TokenSubPath.json", null, timeClaims);
        publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        if (publicKey == null) {
            throw new IllegalStateException("Failed to load /publicKey.pem resource");
        }
    }

    @Test(groups = TEST_GROUP_JWT, description = "validate the custom sub claim is available on the path")
    public void subClaimIsAvailableOnPath() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo((RSAPublicKey) publicKey, TEST_ISSUER);
        contextInfo.setSubjectPath("realm/access/sub/principal");
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        String sub = jwt.getSubject();
        Assert.assertEquals(sub, "microprofile_jwt_principal");
    }

    @Test(groups = TEST_GROUP_JWT, description = "validate the custom sub claim is available on the path with namespace")
    public void subClaimIsAvailableOnPathWithNamespace() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo((RSAPublicKey) publicKey, TEST_ISSUER);
        contextInfo.setSubjectPath("realm/\"https://idp/access\"/sub/principal");
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        String sub = jwt.getSubject();
        Assert.assertEquals(sub, "namespace_microprofile_jwt_principal");
    }

    @Test(groups = TEST_GROUP_JWT, description = "validate the custom sub claim is not available on the long path")
    public void subClaimIsNotAvailableOnTooDeepPath() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo((RSAPublicKey) publicKey, TEST_ISSUER);
        contextInfo.setRequireNamedPrincipal(false);
        contextInfo.setSubjectPath("realm/access/sub/principal/5");
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        Assert.assertNull(jwt.getSubject());
    }

    @Test(groups = TEST_GROUP_JWT, description = "validate the custom sub claim is not available if the claim is not array")
    public void subClaimIsNotAvailableIfClaimIsNotString() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo((RSAPublicKey) publicKey, TEST_ISSUER);
        contextInfo.setRequireNamedPrincipal(false);
        contextInfo.setSubjectPath("realm/access/sub");
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        Assert.assertNull(jwt.getSubject());
    }

    @Test(groups = TEST_GROUP_JWT, description = "validate the custom sub claim is not available on the wrong path")
    public void subClaimIsNotAvailableOnWrongPath() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo((RSAPublicKey) publicKey, TEST_ISSUER);
        contextInfo.setRequireNamedPrincipal(false);
        contextInfo.setSubjectPath("realm/access/user/principal");
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        Assert.assertNull(jwt.getSubject());
    }
}
