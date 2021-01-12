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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.eclipse.microprofile.jwt.Claims;
import org.jose4j.jwt.JwtClaims;

/**
 * Default JWT token validator
 *
 */
public class PrincipalUtils {
    private static final String ROLE_MAPPINGS = "roleMappings";
    /**
     * This pattern uses a positive lookahead to split an expression around the forward slashes
     * ignoring those which are located inside a pair of the double quotes.
     */
    private static final Pattern CLAIM_PATH_PATTERN = Pattern.compile("\\/(?=(?:(?:[^\"]*\"){2})*[^\"]*$)");

    public static void setClaims(JwtClaims claimsSet, String token, JWTAuthContextInfo authContextInfo) {

        claimsSet.setClaim(Claims.raw_token.name(), token);

        if (!claimsSet.hasClaim(Claims.sub.name())) {
            String sub = findSubject(authContextInfo, claimsSet);
            claimsSet.setClaim(Claims.sub.name(), sub);
        }
        Object groupsClaim = claimsSet.getClaimValue(Claims.groups.name());
        if (groupsClaim == null || groupsClaim instanceof Map) {
            List<String> groups = findGroups(authContextInfo, claimsSet);
            claimsSet.setClaim(Claims.groups.name(), groups);
        } else if (groupsClaim instanceof String) {
            claimsSet.setClaim(Claims.groups.name(),
                    splitStringClaimValue(groupsClaim.toString(), authContextInfo));
        }

        // Process the rolesMapping claim
        if (claimsSet.hasClaim(ROLE_MAPPINGS)) {
            mapRoles(claimsSet);
        }
    }

    private static String findSubject(JWTAuthContextInfo authContextInfo, JwtClaims claimsSet) {
        if (authContextInfo.getSubjectPath() != null) {
            final String[] pathSegments = splitClaimPath(authContextInfo.getSubjectPath());
            Object claimValue = findClaimValue(authContextInfo.getSubjectPath(), claimsSet.getClaimsMap(), pathSegments, 0);
            if (claimValue instanceof String) {
                return (String) claimValue;
            } else {
                PrincipalLogging.log.claimAtPathIsNotAString(authContextInfo.getSubjectPath());
            }
        }
        if (authContextInfo.getDefaultSubjectClaim() != null) {
            return authContextInfo.getDefaultSubjectClaim();
        }
        return null;
    }

    private static List<String> findGroups(JWTAuthContextInfo authContextInfo, JwtClaims claimsSet) {
        if (authContextInfo.getGroupsPath() != null) {
            final String[] pathSegments = splitClaimPath(authContextInfo.getGroupsPath());
            Object claimValue = findClaimValue(authContextInfo.getGroupsPath(), claimsSet.getClaimsMap(), pathSegments, 0);

            if (claimValue instanceof List) {
                @SuppressWarnings("unchecked")
                List<String> groups = List.class.cast(claimValue);
                // Force a check that a list contains the string values only
                try {
                    return Arrays.asList(groups.toArray(new String[] {}));
                } catch (ArrayStoreException ex) {
                    PrincipalLogging.log.claimAtPathIsNotAnArrayOfStrings(authContextInfo.getGroupsPath());
                }
            } else if (claimValue instanceof String) {
                return splitStringClaimValue(claimValue.toString(), authContextInfo);
            } else {
                PrincipalLogging.log.claimAtPathIsNeitherAnArrayOfStringsNorString(authContextInfo.getGroupsPath());
            }
        }
        if (authContextInfo.getDefaultGroupsClaim() != null) {
            return Collections.singletonList(authContextInfo.getDefaultGroupsClaim());
        }

        return null;
    }

    private static List<String> splitStringClaimValue(String claimValue, JWTAuthContextInfo authContextInfo) {
        return Arrays.asList(claimValue.split(authContextInfo.getGroupsSeparator()));
    }

    private static String[] splitClaimPath(String claimPath) {
        return claimPath.indexOf('/') > 0 ? CLAIM_PATH_PATTERN.split(claimPath) : new String[] { claimPath };
    }

    private static void mapRoles(JwtClaims claimsSet) {
        try {
            @SuppressWarnings("unchecked")
            Map<String, String> rolesMapping = claimsSet.getClaimValue(ROLE_MAPPINGS, Map.class);
            List<String> groups = claimsSet.getStringListClaimValue(Claims.groups.name());
            List<String> allGroups = new ArrayList<>(groups);
            for (Map.Entry<String, String> mapping : rolesMapping.entrySet()) {
                // If the key group is in groups list, add the mapped role
                if (groups.contains(mapping.getKey())) {
                    allGroups.add(mapping.getValue());
                }
            }
            // Replace the groups with the original groups + mapped roles
            claimsSet.setStringListClaim(Claims.groups.name(), allGroups);
            PrincipalLogging.log.updatedGroups(allGroups);
        } catch (Exception e) {
            PrincipalLogging.log.failedToAccessRolesMappingClaim(e);
        }
    }

    private static Object findClaimValue(String claimPath, Map<String, Object> claimsMap, String[] pathArray, int step) {
        Object claimValue = claimsMap.get(pathArray[step].replace("\"", ""));
        if (claimValue == null) {
            PrincipalLogging.log.claimNotFoundAtPathAtSegment(claimPath, pathArray[step]);
        } else if (step + 1 < pathArray.length) {
            if (claimValue instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> nextMap = (Map<String, Object>) claimValue;
                int nextStep = step + 1;
                return findClaimValue(claimPath, nextMap, pathArray, nextStep);
            } else {
                PrincipalLogging.log.claimValueIsNotAJson(claimPath);
                return null;
            }
        }
        return claimValue;
    }
}
