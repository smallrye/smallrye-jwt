/*
 *   Copyright 2019 Red Hat, Inc, and individual contributors.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */
package io.smallrye.jwt;

import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_GROUP_JWT;
import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_ISSUER;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Set;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.jboss.arquillian.testng.Arquillian;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipalFactory;

/**
 * A more extensive test of the how the token JSON content types are mapped
 * to values via the JsonWebToken implementation.
 */
public class TestTokenWithGroupsPath extends Arquillian {
    /** The test generated JWT token string */
    private static String token;
    /** The /publicKey.pem instance */
    private static PublicKey publicKey;

    @BeforeClass(alwaysRun = true)
    public static void generateToken() throws Exception {
        HashMap<String, Long> timeClaims = new HashMap<>();
        token = TokenUtils.signClaims("/TokenGroupsPath.json", null, timeClaims);
        publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        if (publicKey == null) {
            throw new IllegalStateException("Failed to load /publicKey.pem resource");
        }
    }

    @Test(groups = TEST_GROUP_JWT, description = "validate the groups claim can be mapped from a custom array claim")
    public void groupsIsAvailableInCustomArray() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo((RSAPublicKey) publicKey, TEST_ISSUER);
        contextInfo.setGroupsPath("realm/access/groups/array");
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        Set<String> groups = jwt.getGroups();
        Assert.assertEquals(groups.size(), 1);
        Assert.assertTrue(groups.contains("microprofile_jwt_user"));
    }

    @Test(groups = TEST_GROUP_JWT, description = "validate the groups claim can be mapped from a custom array claim with namespace")
    public void groupsIsAvailableInCustomArrayWithNamespace() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo((RSAPublicKey) publicKey, TEST_ISSUER);
        contextInfo.setGroupsPath("realm/access/\"https://idp/groups\"/array");
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        Set<String> groups = jwt.getGroups();
        Assert.assertEquals(groups.size(), 1);
        Assert.assertTrue(groups.contains("namespace_microprofile_jwt_user"));
    }

    @Test(groups = TEST_GROUP_JWT, description = "validate the groups claim can be mapped from a standard scope claim")
    public void groupsIsAvailableInScopeStringClaim() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo((RSAPublicKey) publicKey, TEST_ISSUER);
        contextInfo.setGroupsPath("scope");
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        Set<String> groups = jwt.getGroups();
        Assert.assertEquals(groups.size(), 2);
        Assert.assertTrue(groups.contains("write"));
        Assert.assertTrue(groups.contains("read"));
    }

    @Test(groups = TEST_GROUP_JWT, description = "validate the groups claim can be mapped from a standard scope claim")
    public void groupsIsAvailableInCommaSeparatedStringClaim() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo((RSAPublicKey) publicKey, TEST_ISSUER);
        contextInfo.setGroupsPath("auth");
        contextInfo.setGroupsSeparator(",");
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        Set<String> groups = jwt.getGroups();
        Assert.assertEquals(groups.size(), 2);
        Assert.assertTrue(groups.contains("write"));
        Assert.assertTrue(groups.contains("read"));
    }

    @Test(groups = TEST_GROUP_JWT, description = "validate the custom groups claim is not available on the long path")
    public void groupsClaimIsNotAvailableOnTooDeepPath() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo((RSAPublicKey) publicKey, TEST_ISSUER);
        contextInfo.setGroupsPath("realm/access/groups/array/5");
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        Assert.assertTrue(jwt.getGroups().isEmpty());
    }

    @Test(groups = TEST_GROUP_JWT, description = "validate the custom groups claim is not available if the claim is not array")
    public void groupsClaimIsNotAvailableIfClaimIsNotArray() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo((RSAPublicKey) publicKey, TEST_ISSUER);
        contextInfo.setGroupsPath("realm/access/groups");
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        Assert.assertTrue(jwt.getGroups().isEmpty());
    }

    @Test(groups = TEST_GROUP_JWT, description = "validate the custom groups claim is not available on the wrong path")
    public void groupsClaimIsNotAvailableOnWrongPath() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo((RSAPublicKey) publicKey, TEST_ISSUER);
        contextInfo.setGroupsPath("realm/access/group/array");
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        Assert.assertTrue(jwt.getGroups().isEmpty());
    }

}
