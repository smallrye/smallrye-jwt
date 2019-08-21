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
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

import org.eclipse.microprofile.jwt.Claims;
import org.jboss.logging.Logger;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.jose4j.lang.UnresolvableKeyException;

/**
 * Default JWT token validator
 *
 */
public class DefaultJWTTokenParser {
    private static final Logger LOGGER = Logger.getLogger(DefaultJWTTokenParser.class);
    private static final String ROLE_MAPPINGS = "roleMappings";
    private volatile VerificationKeyResolver keyResolver;

    public JwtContext parse(final String token, final JWTAuthContextInfo authContextInfo) throws ParseException {

        try {
            JwtConsumerBuilder builder = new JwtConsumerBuilder()
                    .setRequireExpirationTime();

            if (authContextInfo.getWhitelistAlgorithms().isEmpty()) {
                builder.setJwsAlgorithmConstraints(
                        new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST,
                                AlgorithmIdentifiers.RSA_USING_SHA256));
            } else {
                builder.setJwsAlgorithmConstraints(
                        new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST,
                                authContextInfo.getWhitelistAlgorithms().toArray(new String[0])));
            }

            if (authContextInfo.isRequireIssuer()) {
                builder.setExpectedIssuer(true, authContextInfo.getIssuedBy());
            } else {
                builder.setExpectedIssuer(false, null);
            }
            if (authContextInfo.getSignerKey() != null) {
                builder.setVerificationKey(authContextInfo.getSignerKey());
            } else {
                builder.setVerificationKeyResolver(getKeyResolver(authContextInfo));
            }

            if (authContextInfo.getExpGracePeriodSecs() > 0) {
                builder.setAllowedClockSkewInSeconds(authContextInfo.getExpGracePeriodSecs());
            } else {
                builder.setEvaluationTime(NumericDate.fromSeconds(0));
            }

            setExpectedAudience(builder, authContextInfo);

            JwtConsumer jwtConsumer = builder.build();

            //  Validate the JWT and process it to the Claims
            JwtContext jwtContext = jwtConsumer.process(token);
            JwtClaims claimsSet = jwtContext.getJwtClaims();

            claimsSet.setClaim(Claims.raw_token.name(), token);

            if (!claimsSet.hasClaim(Claims.sub.name())) {
                String sub = findSubject(authContextInfo, claimsSet);
                claimsSet.setClaim(Claims.sub.name(), sub);
            }

            if (authContextInfo.isRequireNamedPrincipal()) {
                checkNameClaims(jwtContext);
            }

            if (!claimsSet.hasClaim(Claims.groups.name())) {
                List<String> groups = findGroups(authContextInfo, claimsSet);
                claimsSet.setClaim(Claims.groups.name(), groups);
            }

            // Process the rolesMapping claim
            if (claimsSet.hasClaim(ROLE_MAPPINGS)) {
                mapRoles(claimsSet);
            }

            return jwtContext;
        } catch (InvalidJwtException | UnresolvableKeyException e) {
            LOGGER.warnf("Token is invalid: %s", e.getMessage());
            throw new ParseException("Failed to verify token", e);
        }

    }

    void setExpectedAudience(JwtConsumerBuilder builder, JWTAuthContextInfo authContextInfo) {
        final Set<String> expectedAudience = authContextInfo.getExpectedAudience();

        if (expectedAudience != null) {
            builder.setExpectedAudience(expectedAudience.toArray(new String[0]));
        } else {
            builder.setSkipDefaultAudienceValidation();
        }
    }

    private void checkNameClaims(JwtContext jwtContext) throws InvalidJwtException {
        JwtClaims claimsSet = jwtContext.getJwtClaims();
        final boolean hasPrincipalClaim = Stream.of(Claims.sub.name(), Claims.upn.name(), Claims.preferred_username.name())
                .map(claimsSet::getClaimValue)
                .anyMatch(Objects::nonNull);

        if (!hasPrincipalClaim) {
            throw new InvalidJwtException("No claim exists in sub, upn or preferred_username", new ArrayList<>(),
                    jwtContext);
        }
    }

    private String findSubject(JWTAuthContextInfo authContextInfo, JwtClaims claimsSet) {
        if (authContextInfo.getSubjectPath() != null) {
            final String[] pathSegments = authContextInfo.getSubjectPath().split("/");
            Object claimValue = findClaimValue(authContextInfo.getSubjectPath(), claimsSet.getClaimsMap(), pathSegments, 0);
            if (claimValue instanceof String) {
                return (String) claimValue;
            } else {
                LOGGER.warnf("Claim value at the path %s is not a String", authContextInfo.getSubjectPath());
            }
        }
        if (authContextInfo.getDefaultSubjectClaim() != null) {
            return authContextInfo.getDefaultSubjectClaim();
        }
        return null;
    }

    private List<String> findGroups(JWTAuthContextInfo authContextInfo, JwtClaims claimsSet) {
        if (authContextInfo.getGroupsPath() != null) {
            final String[] pathSegments = authContextInfo.getGroupsPath().split("/");
            Object claimValue = findClaimValue(authContextInfo.getGroupsPath(), claimsSet.getClaimsMap(), pathSegments, 0);

            if (claimValue instanceof List) {
                @SuppressWarnings("unchecked")
                List<String> groups = List.class.cast(claimValue);
                // Force a check that a list contains the string values only
                try {
                    return Arrays.asList(groups.toArray(new String[] {}));
                } catch (ArrayStoreException ex) {
                    LOGGER.warnf("Claim value at the path %s is not an array of strings",
                            authContextInfo.getGroupsPath());
                }
            } else if (claimValue instanceof String) {
                return Arrays.asList(((String) claimValue).split(authContextInfo.getGroupsSeparator()));
            } else {
                LOGGER.warnf("Claim value at the path %s is neither an array of strings nor string",
                        authContextInfo.getGroupsPath());
            }
        }
        if (authContextInfo.getDefaultGroupsClaim() != null) {
            return Collections.singletonList(authContextInfo.getDefaultGroupsClaim());
        }

        return null;
    }

    private void mapRoles(JwtClaims claimsSet) {
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
            LOGGER.infof("Updated groups to: %s", allGroups);
        } catch (Exception e) {
            LOGGER.warnf(e, "Failed to access rolesMapping claim");
        }
    }

    private Object findClaimValue(String claimPath, Map<String, Object> claimsMap, String[] pathArray, int step) {
        Object claimValue = claimsMap.get(pathArray[step]);
        if (claimValue == null) {
            LOGGER.warnf("No claim exists at the path %s at segment %s", claimPath, pathArray[step]);
        } else if (step + 1 < pathArray.length) {
            if (claimValue instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> nextMap = (Map<String, Object>) claimValue;
                int nextStep = step + 1;
                return findClaimValue(claimPath, nextMap, pathArray, nextStep);
            } else {
                LOGGER.warnf("Claim value at the path %s is not a json object", claimPath);
                return null;
            }
        }
        return claimValue;
    }

    protected VerificationKeyResolver getKeyResolver(JWTAuthContextInfo authContextInfo) throws UnresolvableKeyException {
        if (keyResolver == null) {
            synchronized (this) {
                if (keyResolver == null)
                    keyResolver = new KeyLocationResolver(authContextInfo);
            }
        }
        return keyResolver;
    }
}
