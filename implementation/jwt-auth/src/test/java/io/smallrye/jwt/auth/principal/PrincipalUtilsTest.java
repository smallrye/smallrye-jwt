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
package io.smallrye.jwt.auth.principal;

import static org.junit.jupiter.api.Assertions.assertIterableEquals;

import java.util.List;

import org.eclipse.microprofile.jwt.Claims;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.opentest4j.AssertionFailedError;

@ExtendWith(MockitoExtension.class)
class PrincipalUtilsTest {

    private static final List<String> rolesInGroupsClaim = List.of("group1", "group2");
    private static final String rolesInGroupsClaimAsString = "group1 group2";
    private static final String defaultRole = "default1";
    private static final List<String> rolesInDefaultGroup = List.of(defaultRole);
    private static final List<String> rolesInCustomGroupsClaim = List.of("custom1", "custom2");
    private static final String rolesInCustomGroupsClaimAsString = "custom1 custom2";

    private static final List<TestData> tests = List.of(
            new TestData("group claim is set, custom groups are not set",
                    rolesInGroupsClaim,
                    rolesInGroupsClaim, null, false, null),
            new TestData("group claim is set, custom groups are not set, default role is set",
                    rolesInGroupsClaim,
                    rolesInGroupsClaim, null, false, defaultRole),

            new TestData("group claim is set, custom groups are set",
                    rolesInCustomGroupsClaim,
                    rolesInGroupsClaim, rolesInCustomGroupsClaim, true, null),
            new TestData("group claim is set, custom groups are set, default role is set",
                    rolesInCustomGroupsClaim,
                    rolesInGroupsClaim, rolesInCustomGroupsClaim, true, defaultRole),

            new TestData("group claim is set, custom groups are set but empty",
                    rolesInGroupsClaim,
                    rolesInGroupsClaim, null, true, null),
            new TestData("group claim is set, custom groups are set but empty, default role is set",
                    rolesInDefaultGroup,
                    rolesInGroupsClaim, null, true, defaultRole),

            new TestData("group claim is empty, custom groups are set",
                    rolesInCustomGroupsClaim,
                    null, rolesInCustomGroupsClaim, true, null),
            new TestData("group claim is empty, custom groups are set, and default role is set",
                    rolesInCustomGroupsClaim,
                    null, rolesInCustomGroupsClaim, true, defaultRole),

            new TestData("group claim is empty, custom groups are not set",
                    null,
                    null, null, false, null),
            new TestData("group claim is empty, custom groups are not set, default role is set",
                    rolesInDefaultGroup,
                    null, null, false, defaultRole),

            new TestData("group claim is empty, custom groups are set but empty",
                    null,
                    null, null, true, null),
            new TestData("group claim is empty, custom groups are set but empty, default role is set",
                    rolesInDefaultGroup,
                    null, null, true, defaultRole),

            new TestData("group claim is set as string, custom groups are not set",
                    rolesInGroupsClaim,
                    rolesInGroupsClaimAsString, null, false, null),
            new TestData("group claim is empty, custom groups are set as string",
                    rolesInCustomGroupsClaim,
                    null, rolesInCustomGroupsClaimAsString, true, null));

    @Test
    void testGroupsClaimSettings() throws Exception {
        for (TestData td : tests) {
            JwtClaims claimSet = td.getClaimSet();
            PrincipalUtils.setClaims(claimSet, td.getToken(), td.getAuthContextInfo());

            @SuppressWarnings("unchecked")
            List<String> actualRoles = List.class.cast(claimSet.getClaimValue(Claims.groups.name()));
            try {
                assertIterableEquals(td.getExpectedRoles(), actualRoles);
            } catch (AssertionFailedError e) {
                throw new AssertionFailedError(td.getName(), e);
            }
        }
    }

    private static class TestData {

        private static final String CUSTOM_GROUPS_PATH = "testroles";

        private final String name;
        private final List<String> expectedRoles;
        private final Object rolesInGroupsClaim;
        private final Object rolesInCustomClaim;
        private final boolean setCustomGroupsPath;
        private final String defaultGroupsClaim;

        public TestData(String name, List<String> expectedRoles, Object rolesInGroupsClaim, Object rolesInCustomClaim,
                boolean setCustomGroupsPath, String defaultGroupsClaim) {
            this.name = name;
            this.expectedRoles = expectedRoles;
            this.rolesInGroupsClaim = rolesInGroupsClaim;
            this.rolesInCustomClaim = rolesInCustomClaim;
            this.setCustomGroupsPath = setCustomGroupsPath;
            this.defaultGroupsClaim = defaultGroupsClaim;
        }

        public String getName() {
            return name;
        }

        public List<String> getExpectedRoles() {
            return expectedRoles;
        }

        public JwtClaims getClaimSet() {
            JwtClaims claimSet = new JwtClaims();
            if (rolesInGroupsClaim != null) {
                claimSet.setClaim(Claims.groups.name(), rolesInGroupsClaim);
            }
            if (rolesInCustomClaim != null) {
                claimSet.setClaim(CUSTOM_GROUPS_PATH, rolesInCustomClaim);
            }
            return claimSet;
        }

        public String getToken() {
            return "test.token.signature";
        }

        public JWTAuthContextInfo getAuthContextInfo() {
            JWTAuthContextInfo authContextInfo = new JWTAuthContextInfo();
            if (setCustomGroupsPath) {
                authContextInfo.setGroupsPath(CUSTOM_GROUPS_PATH);
            }
            authContextInfo.setDefaultGroupsClaim(defaultGroupsClaim);
            return authContextInfo;
        }

    }

}
