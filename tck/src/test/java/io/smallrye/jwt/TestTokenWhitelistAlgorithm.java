package io.smallrye.jwt;

import static java.util.Collections.singletonList;
import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_GROUP_JWT;
import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_ISSUER;
import static org.jose4j.jws.AlgorithmIdentifiers.HMAC_SHA256;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Optional;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.jboss.arquillian.testng.Arquillian;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipalFactory;

public class TestTokenWhitelistAlgorithm extends Arquillian {
    private static String token;
    private static PublicKey publicKey;

    @BeforeClass(alwaysRun = true)
    public static void generateToken() throws Exception {
        HashMap<String, Long> timeClaims = new HashMap<>();
        token = TokenUtils.generateTokenString("/Token1.json", null, timeClaims);
        publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        if (publicKey == null) {
            throw new IllegalStateException("Failed to load /publicKey.pem resource");
        }
    }

    @Test(groups = TEST_GROUP_JWT, description = "validate the token with default algorithm")
    public void tokenDefaultAlgorithm() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo((RSAPublicKey) publicKey, TEST_ISSUER);
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        String sub = jwt.getSubject();
        Assert.assertEquals(sub, "24400320");
    }

    @Test(groups = TEST_GROUP_JWT, description = "ignore no valid algorithm")
    public void ignoreNoValidAlgorithm() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo((RSAPublicKey) publicKey, TEST_ISSUER);
        SmallryeJwtUtils.setWhitelistAlgorithms(contextInfo, Optional.of(singletonList(HMAC_SHA256)));
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        String sub = jwt.getSubject();
        Assert.assertEquals(sub, "24400320");
    }
}
