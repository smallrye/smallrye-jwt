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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import jakarta.json.JsonArray;
import jakarta.json.JsonNumber;
import jakarta.json.JsonObject;

import org.eclipse.microprofile.jwt.Claims;
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
class TestTokenClaimTypes {
    /** The test generated JWT token string */
    private static String token;
    /** The corresponding JsonWebToken */
    private static JsonWebToken jwt;
    /** The /publicKey.pem instance */
    private static PublicKey publicKey;

    // Time claims in the token
    private static Long iatClaim;
    private static Long authTimeClaim;
    private static Long expClaim;

    @BeforeAll
    static void generateToken() throws Exception {
        Map<String, Long> timeClaims = new HashMap<>();
        token = TokenUtils.signClaims("/Token1.json", SignatureAlgorithm.RS256, null, timeClaims);
        iatClaim = timeClaims.get(Claims.iat.name());
        authTimeClaim = timeClaims.get(Claims.auth_time.name());
        expClaim = timeClaims.get(Claims.exp.name());

        publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        if (publicKey == null) {
            throw new IllegalStateException("Failed to load /publicKey.pem resource");
        }

        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo((RSAPublicKey) publicKey, TEST_ISSUER);
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        jwt = factory.parse(token, contextInfo);
    }

    @Test
    void validateRawToken() {
        assertEquals(token, jwt.getRawToken());
    }

    @Test
    void validateIssuer() {
        assertEquals(TEST_ISSUER, jwt.getIssuer());
        assertEquals(TEST_ISSUER, jwt.getClaim(Claims.iss.name()));
    }

    @Test
    void validateSubject() {
        assertEquals("24400320", jwt.getSubject());
        assertEquals("24400320", jwt.getClaim(Claims.sub.name()));
    }

    @Test
    void validateTokenID() {
        assertEquals("a-123", jwt.getTokenID());
        assertEquals("a-123", jwt.getClaim(Claims.jti.name()));
    }

    @Test
    void validateAudience() {
        Set<String> audience = jwt.getAudience();
        HashSet<String> actual = new HashSet<>();
        actual.add("s6BhdRkqt3");
        assertEquals(actual, audience);
        assertEquals(actual, jwt.getClaim(Claims.aud.name()));
    }

    @Test
    void validateExpirationTime() {
        assertEquals(expClaim.longValue(), jwt.getExpirationTime());
        long exp = jwt.getClaim(Claims.exp.name());
        assertEquals(expClaim.longValue(), exp);
    }

    @Test
    void validateGroups() {
        Set<String> groups = jwt.getGroups();
        SortedSet<String> sortedGroups = new TreeSet<>(groups);
        SortedSet<String> actual = new TreeSet<>();
        actual.add("Echoer");
        actual.add("Tester");
        actual.add("group1");
        actual.add("group2");
        assertEquals(actual, sortedGroups);
        Set<String> groups2 = jwt.getClaim(Claims.groups.name());
        SortedSet<String> sortedGroups2 = new TreeSet<>(groups2);
        assertEquals(actual, sortedGroups2);
    }

    @Test
    void validateIssuedAtTime() {
        assertEquals(iatClaim.longValue(), jwt.getIssuedAtTime());
        long iat = jwt.getClaim(Claims.iat.name());
        assertEquals(iatClaim.longValue(), iat);
    }

    @Test
    void validateAuthTime() {
        long authTime = jwt.getClaim(Claims.auth_time.name());
        assertEquals(authTimeClaim.longValue(), authTime);
    }

    @Test
    void validateClaimNames() {
        String[] expected = { "iss", "jti", "sub", "upn", "preferred_username",
                "aud", "exp", "iat", "roles", "groups", "customString", "customInteger",
                "customStringArray", "customIntegerArray", "customDoubleArray",
                "customObject" };
        Set<String> claimNames = jwt.getClaimNames();
        HashSet<String> missingNames = new HashSet<>();
        for (String name : expected) {
            if (!claimNames.contains(name)) {
                missingNames.add(name);
            }
        }
        assertTrue(missingNames.size() == 0, "There should be no missing claim names");
    }

    @Test
    void validateCustomString() {
        String value = jwt.getClaim("customString");
        assertEquals("customStringValue", value);
    }

    @Test
    void validateCustomInteger() {
        JsonNumber value = jwt.getClaim("customInteger");
        assertEquals(123456789L, value.longValue());
    }

    @Test
    void validateCustomDouble() {
        JsonNumber value = jwt.getClaim("customDouble");
        assertEquals(3.141592653589793, value.doubleValue(), 0.000000001);
    }

    @Test
    void validateCustomStringArray() {
        JsonArray value = jwt.getClaim("customStringArray");
        assertEquals("value0", value.getString(0));
        assertEquals("value1", value.getString(1));
        assertEquals("value2", value.getString(2));
    }

    @Test
    void validateCustomIntegerArray() {
        JsonArray value = jwt.getClaim("customIntegerArray");
        assertEquals(0, value.getInt(0));
        assertEquals(1, value.getInt(1));
        assertEquals(2, value.getInt(2));
        assertEquals(3, value.getInt(3));
    }

    @Test
    void validateCustomDoubleArray() {
        JsonArray value = jwt.getClaim("customDoubleArray");
        assertEquals(0.1, value.getJsonNumber(0).doubleValue(), 0.000001);
        assertEquals(1.1, value.getJsonNumber(1).doubleValue(), 0.000001);
        assertEquals(2.2, value.getJsonNumber(2).doubleValue(), 0.000001);
        assertEquals(3.3, value.getJsonNumber(3).doubleValue(), 0.000001);
        assertEquals(4.4, value.getJsonNumber(4).doubleValue(), 0.000001);
    }

    @Test
    void validateCustomObject() {
        JsonObject value = jwt.getClaim("customObject");
        JsonObject myService = value.getJsonObject("my-service");
        assertNotNull(myService);
        JsonArray groups = myService.getJsonArray("groups");
        assertNotNull(groups);
        assertEquals("group1", groups.getString(0));
        assertEquals("group2", groups.getString(1));
        JsonArray roles = myService.getJsonArray("roles");
        assertNotNull(roles);
        assertEquals("role-in-my-service", roles.getString(0));

        JsonObject serviceB = value.getJsonObject("service-B");
        assertNotNull(serviceB);
        JsonArray rolesB = serviceB.getJsonArray("roles");
        assertNotNull(roles);
        assertEquals("role-in-B", rolesB.getString(0));

        JsonObject serviceC = value.getJsonObject("service-C");
        assertNotNull(serviceC);
        JsonArray groupsC = serviceC.getJsonArray("groups");
        assertNotNull(groups);
        assertEquals("groupC", groupsC.getString(0));
        assertEquals("web-tier", groupsC.getString(1));
    }

    @Test
    void validateNameIsUPN() {
        assertEquals("jdoe@example.com", jwt.getName());
    }

    @Test
    void validateNameIsPreferredName() throws Exception {
        String token2 = TokenUtils.signClaims("/usePreferredName.json");
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo((RSAPublicKey) publicKey, TEST_ISSUER);
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt2 = factory.parse(token2, contextInfo);
        assertEquals("jdoe", jwt2.getName());
    }

    @Test
    void validateNameIsSubject() throws Exception {
        String token2 = TokenUtils.signClaims("/useSubject.json");
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo((RSAPublicKey) publicKey, TEST_ISSUER);
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JsonWebToken jwt2 = factory.parse(token2, contextInfo);
        assertEquals("24400320", jwt2.getName());
    }
}
