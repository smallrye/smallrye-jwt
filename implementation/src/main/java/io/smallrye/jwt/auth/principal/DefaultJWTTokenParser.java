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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.eclipse.microprofile.jwt.Claims;
import org.jboss.logging.Logger;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.jose4j.lang.JoseException;

/**
 * Default JWT token validator
 *
 */
public class DefaultJWTTokenParser {
    private static Logger logger = Logger.getLogger(DefaultJWTTokenParser.class);
    private static final String ROLE_MAPPINGS = "roleMappings";

    private HttpsJwks httpsJwks;

    public JwtContext parse(final String token, final JWTAuthContextInfo authContextInfo) throws ParseException {

        try {
            JwtConsumerBuilder builder = new JwtConsumerBuilder()
                    .registerValidator(new CustomSubValidator(authContextInfo))
                    .setRequireExpirationTime()
                    .setSkipDefaultAudienceValidation();

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
            } else if (authContextInfo.isFollowMpJwt11Rules()) {
                builder.setVerificationKeyResolver(new KeyLocationResolver(authContextInfo.getJwksUri()));
            } else {
                final List<JsonWebKey> jsonWebKeys = loadJsonWebKeys(authContextInfo);
                builder.setVerificationKeyResolver(new JwksVerificationKeyResolver(jsonWebKeys));
            }

            if (authContextInfo.getExpGracePeriodSecs() > 0) {
                builder.setAllowedClockSkewInSeconds(authContextInfo.getExpGracePeriodSecs());
            } else {
                builder.setEvaluationTime(NumericDate.fromSeconds(0));
            }

            JwtConsumer jwtConsumer = builder.build();

            //  Validate the JWT and process it to the Claims
            JwtContext jwtContext = jwtConsumer.process(token);
            JwtClaims claimsSet = jwtContext.getJwtClaims();

            claimsSet.setClaim(Claims.raw_token.name(), token);

            if (!claimsSet.hasClaim(Claims.sub.name())) {
                String sub = ClaimSubPathResolver.checkSubPath(authContextInfo, claimsSet);
                if (sub == null && authContextInfo.getDefaultSubClaim() != null) {
                    sub = ClaimSubPathResolver.findSub(authContextInfo, claimsSet.getClaimsMap(),
                            new String[] { authContextInfo.getDefaultSubClaim() }, 0);
                }
                claimsSet.setClaim(Claims.sub.name(), sub);
            }

            if (!claimsSet.hasClaim(Claims.groups.name())) {
                List<String> groups = checkGroupsPath(authContextInfo, claimsSet);
                if (groups == null && authContextInfo.getDefaultGroupsClaim() != null) {
                    groups = Collections.singletonList(authContextInfo.getDefaultGroupsClaim());
                }
                claimsSet.setClaim(Claims.groups.name(), groups);
            }

            // Process the rolesMapping claim
            if (claimsSet.hasClaim(ROLE_MAPPINGS)) {
                try {
                    @SuppressWarnings("unchecked")
                    Map<String, String> rolesMapping = claimsSet.getClaimValue(ROLE_MAPPINGS, Map.class);
                    List<String> groups = claimsSet.getStringListClaimValue(Claims.groups.name());
                    List<String> allGroups = new ArrayList<>(groups);
                    for (String key : rolesMapping.keySet()) {
                        // If the key group is in groups list, add the mapped role
                        if (groups.contains(key)) {
                            String toRole = rolesMapping.get(key);
                            allGroups.add(toRole);
                        }
                    }
                    // Replace the groups with the original groups + mapped roles
                    claimsSet.setStringListClaim("groups", allGroups);
                    logger.infof("Updated groups to: %s", allGroups);
                } catch (Exception e) {
                    logger.warnf(e, "Failed to access rolesMapping claim");
                }
            }

            return jwtContext;
        } catch (InvalidJwtException e) {
            logger.warnf("Token is invalid: %s", e.getMessage());
            throw new ParseException("Failed to verify token", e);
        }

    }

    private List<String> checkGroupsPath(JWTAuthContextInfo authContextInfo, JwtClaims claimsSet) {
        if (authContextInfo.getGroupsPath() != null) {
            final String[] pathSegments = authContextInfo.getGroupsPath().split("/");
            return findGroups(authContextInfo, claimsSet.getClaimsMap(), pathSegments, 0);
        }
        return null;
    }

    private List<String> findGroups(JWTAuthContextInfo authContextInfo,
            Map<String, Object> claimsMap,
            String[] pathArray,
            int step) {

        Object claimValue = claimsMap.get(pathArray[step]);
        if (claimValue == null) {
            logger.warnf("No claim exists at the path %s at segment %s",
                    authContextInfo.getGroupsPath(), pathArray[step]);
        } else if (step + 1 < pathArray.length) {
            if (claimValue instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> nextMap = (Map<String, Object>) claimValue;
                int nextStep = step + 1;
                return findGroups(authContextInfo, nextMap, pathArray, nextStep);
            } else {
                logger.warnf("Claim value at the path %s is not a json object", authContextInfo.getGroupsPath());
            }
        } else if (claimValue instanceof List) {
            // last segment
            try {
                @SuppressWarnings("unchecked")
                List<String> groups = (List<String>) claimValue;
                return groups;
            } catch (ClassCastException e) {
                logger.warnf("Claim value at the path %s is not an array of strings", authContextInfo.getGroupsPath());
            }
        } else {
            // last segment
            logger.warnf("Claim value at the path %s is not an array", authContextInfo.getGroupsPath());
        }
        return null;
    }

    protected List<JsonWebKey> loadJsonWebKeys(JWTAuthContextInfo authContextInfo) {
        synchronized (this) {
            if (authContextInfo.getJwksUri() == null) {
                return Collections.emptyList();
            }

            if (httpsJwks == null) {
                httpsJwks = new HttpsJwks(authContextInfo.getJwksUri());
                httpsJwks.setDefaultCacheDuration(authContextInfo.getJwksRefreshInterval().longValue() * 60L);
            }
        }

        try {
            return httpsJwks.getJsonWebKeys().stream()
                    .filter(jsonWebKey -> "sig".equals(jsonWebKey.getUse())) // only signing keys are relevant
                    .filter(jsonWebKey -> "RS256".equals(jsonWebKey.getAlgorithm())) // MP-JWT dictates RS256 only
                    .collect(Collectors.toList());
        } catch (IOException | JoseException e) {
            throw new IllegalStateException(String.format("Unable to fetch JWKS from %s.",
                    authContextInfo.getJwksUri()), e);
        }
    }
}
