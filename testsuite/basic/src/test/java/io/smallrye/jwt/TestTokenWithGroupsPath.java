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

import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_ISSUER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Set;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.eclipse.microprofile.jwt.tck.util.SignatureAlgorithm;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipalFactory;

/**
 * A more extensive test of the how the token JSON content types are mapped
 * to values via the JsonWebToken implementation.
 */
class TestTokenWithGroupsPath {
    /** The test generated JWT token string */
    private static String token;
    /** The /publicKey.pem instance */
    private static PublicKey publicKey;

    @BeforeAll
    static void generateToken() throws Exception {
        HashMap<String, Long> timeClaims = new HashMap<>();
        token = TokenUtils.signClaims("/TokenGroupsPath.json", SignatureAlgorithm.RS256, null, timeClaims);
        publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        if (publicKey == null) {
            throw new IllegalStateException("Failed to load /publicKey.pem resource");
        }
    }

    @Test
    void groupsIsAvailableInCustomArray() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo((RSAPublicKey) publicKey, TEST_ISSUER);
        contextInfo.setGroupsPath("realm/access/groups/array");
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        Set<String> groups = jwt.getGroups();
        assertEquals(groups.size(), 1);
        assertTrue(groups.contains("microprofile_jwt_user"));
    }

    @Test
    void groupsIsAvailableInCustomArrayWithNamespace() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo((RSAPublicKey) publicKey, TEST_ISSUER);
        contextInfo.setGroupsPath("realm/access/\"https://idp/groups\"/array");
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        Set<String> groups = jwt.getGroups();
        assertEquals(groups.size(), 1);
        assertTrue(groups.contains("namespace_microprofile_jwt_user"));
    }

    @Test
    void groupsIsAvailableInScopeStringClaim() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo((RSAPublicKey) publicKey, TEST_ISSUER);
        contextInfo.setGroupsPath("scope");
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        Set<String> groups = jwt.getGroups();
        assertEquals(groups.size(), 2);
        assertTrue(groups.contains("write"));
        assertTrue(groups.contains("read"));
    }

    @Test
    void groupsIsAvailableInCommaSeparatedStringClaim() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo((RSAPublicKey) publicKey, TEST_ISSUER);
        contextInfo.setGroupsPath("auth");
        contextInfo.setGroupsSeparator(",");
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        Set<String> groups = jwt.getGroups();
        assertEquals(groups.size(), 2);
        assertTrue(groups.contains("write"));
        assertTrue(groups.contains("read"));
    }

    @Test
    void groupsClaimIsNotAvailableOnTooDeepPath() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo((RSAPublicKey) publicKey, TEST_ISSUER);
        contextInfo.setGroupsPath("realm/access/groups/array/5");
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        assertTrue(jwt.getGroups().isEmpty());
    }

    @Test
    void groupsClaimIsNotAvailableIfClaimIsNotArray() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo((RSAPublicKey) publicKey, TEST_ISSUER);
        contextInfo.setGroupsPath("realm/access/groups");
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        assertTrue(jwt.getGroups().isEmpty());
    }

    @Test
    void groupsClaimIsNotAvailableOnWrongPath() throws Exception {
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo((RSAPublicKey) publicKey, TEST_ISSUER);
        contextInfo.setGroupsPath("realm/access/group/array");
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt = factory.parse(token, contextInfo);
        assertTrue(jwt.getGroups().isEmpty());
    }
}
