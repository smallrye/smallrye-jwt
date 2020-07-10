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

import static java.util.Collections.emptyList;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.eclipse.microprofile.jwt.Claims;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.keys.resolvers.DecryptionKeyResolver;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.UnresolvableKeyException;

/**
 * Default JWT token validator
 *
 */
public class DefaultJWTTokenParser {
    private static final String ROLE_MAPPINGS = "roleMappings";
    /**
     * This pattern uses a positive lookahead to split an expression around the forward slashes
     * ignoring those which are located inside a pair of the double quotes.
     */
    private static final Pattern CLAIM_PATH_PATTERN = Pattern.compile("\\/(?=(?:(?:[^\"]*\"){2})*[^\"]*$)");

    private volatile VerificationKeyResolver keyResolver;
    private volatile DecryptionKeyResolver decryptionKeyResolver;

    public JwtContext parse(final String token, final JWTAuthContextInfo authContextInfo) throws ParseException {

        String tokenSequence = token;
        ProtectionLevel level = getProtectionLevel(authContextInfo);

        if (level == ProtectionLevel.SIGN_ENCRYPT) {
            tokenSequence = decryptSignedToken(tokenSequence, authContextInfo);
            level = ProtectionLevel.SIGN;
        }
        return parseClaims(tokenSequence, authContextInfo, level);

    }

    private String decryptSignedToken(String token, JWTAuthContextInfo authContextInfo) throws ParseException {
        try {
            JsonWebEncryption jwe = new JsonWebEncryption();
            jwe.setAlgorithmConstraints(
                    new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT,
                            authContextInfo.getKeyEncryptionAlgorithm().getAlgorithm()));
            if (authContextInfo.getPrivateDecryptionKey() != null) {
                jwe.setKey(authContextInfo.getPrivateDecryptionKey());
            } else if (authContextInfo.getSecretDecryptionKey() != null) {
                jwe.setKey(authContextInfo.getSecretDecryptionKey());
            } else {
                jwe.setKey(getDecryptionKeyResolver(authContextInfo).resolveKey(jwe, null));
            }
            jwe.setCompactSerialization(token);
            if (!"JWT".equals(jwe.getContentTypeHeaderValue())) {
                PrincipalLogging.log.encryptedTokenSequenceInvalid();
                throw PrincipalMessages.msg.encryptedTokenSequenceInvalid();
            }
            return jwe.getPlaintextString();
        } catch (UnresolvableKeyException e) {
            PrincipalLogging.log.decryptionKeyUnresolvable();
            throw PrincipalMessages.msg.decryptionKeyUnresolvable();
        } catch (JoseException e) {
            PrincipalLogging.log.encryptedTokenSequenceInvalid();
            throw PrincipalMessages.msg.encryptedTokenSequenceInvalid();
        }
    }

    private JwtContext parseClaims(String token, JWTAuthContextInfo authContextInfo, ProtectionLevel level)
            throws ParseException {
        try {
            JwtConsumerBuilder builder = new JwtConsumerBuilder();

            if (level == ProtectionLevel.SIGN) {
                if (authContextInfo.getPublicVerificationKey() != null) {
                    builder.setVerificationKey(authContextInfo.getPublicVerificationKey());
                } else if (authContextInfo.getSecretVerificationKey() != null) {
                    builder.setVerificationKey(authContextInfo.getSecretVerificationKey());
                } else {
                    builder.setVerificationKeyResolver(getVerificationKeyResolver(authContextInfo));
                }
                builder.setJwsAlgorithmConstraints(
                        new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT,
                                authContextInfo.getSignatureAlgorithm().getAlgorithm()));
            } else {
                builder.setEnableRequireEncryption();
                builder.setDisableRequireSignature();
                if (authContextInfo.getPrivateDecryptionKey() != null) {
                    builder.setDecryptionKey(authContextInfo.getPrivateDecryptionKey());
                } else if (authContextInfo.getSecretDecryptionKey() != null) {
                    builder.setDecryptionKey(authContextInfo.getSecretDecryptionKey());
                } else {
                    builder.setDecryptionKeyResolver(getDecryptionKeyResolver(authContextInfo));
                }
                builder.setJweAlgorithmConstraints(
                        new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT,
                                authContextInfo.getKeyEncryptionAlgorithm().getAlgorithm()));
            }

            builder.setRequireExpirationTime();

            builder.setRequireIssuedAt();

            if (authContextInfo.getIssuedBy() != null) {
                builder.setExpectedIssuer(authContextInfo.getIssuedBy());
            }

            if (authContextInfo.getExpGracePeriodSecs() > 0) {
                builder.setAllowedClockSkewInSeconds(authContextInfo.getExpGracePeriodSecs());
            } else {
                builder.setEvaluationTime(NumericDate.fromSeconds(0));
            }

            setExpectedAudience(builder, authContextInfo);

            if (authContextInfo.isRelaxVerificationKeyValidation()) {
                builder.setRelaxVerificationKeyValidation();
            }
            JwtConsumer jwtConsumer = builder.build();

            //  Validate the JWT and process it to the Claims
            JwtContext jwtContext = jwtConsumer.process(token);
            JwtClaims claimsSet = jwtContext.getJwtClaims();

            verifyIatAndExpAndTimeToLive(authContextInfo, claimsSet);
            verifyRequiredClaims(authContextInfo, jwtContext);

            claimsSet.setClaim(Claims.raw_token.name(), token);

            if (!claimsSet.hasClaim(Claims.sub.name())) {
                String sub = findSubject(authContextInfo, claimsSet);
                claimsSet.setClaim(Claims.sub.name(), sub);
            }

            if (authContextInfo.isRequireNamedPrincipal()) {
                checkNameClaims(jwtContext);
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

            return jwtContext;
        } catch (InvalidJwtException e) {
            PrincipalLogging.log.tokenInvalid();
            throw PrincipalMessages.msg.failedToVerifyToken(e);
        } catch (UnresolvableKeyException e) {
            PrincipalLogging.log.verificationKeyUnresolvable();
            throw PrincipalMessages.msg.failedToVerifyToken(e);
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
        final boolean hasPrincipalClaim = claimsSet.getClaimValue(Claims.sub.name()) != null ||
                claimsSet.getClaimValue(Claims.upn.name()) != null ||
                claimsSet.getClaimValue(Claims.preferred_username.name()) != null;

        if (!hasPrincipalClaim) {
            throw PrincipalMessages.msg.claimNotFound(s -> new InvalidJwtException(s, emptyList(), jwtContext));
        }
    }

    private String findSubject(JWTAuthContextInfo authContextInfo, JwtClaims claimsSet) {
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

    private List<String> findGroups(JWTAuthContextInfo authContextInfo, JwtClaims claimsSet) {
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

    private List<String> splitStringClaimValue(String claimValue, JWTAuthContextInfo authContextInfo) {
        return Arrays.asList(claimValue.split(authContextInfo.getGroupsSeparator()));
    }

    private static String[] splitClaimPath(String claimPath) {
        return claimPath.indexOf('/') > 0 ? CLAIM_PATH_PATTERN.split(claimPath) : new String[] { claimPath };
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
            PrincipalLogging.log.updatedGroups(allGroups);
        } catch (Exception e) {
            PrincipalLogging.log.failedToAccessRolesMappingClaim(e);
        }
    }

    private Object findClaimValue(String claimPath, Map<String, Object> claimsMap, String[] pathArray, int step) {
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

    private void verifyIatAndExpAndTimeToLive(JWTAuthContextInfo authContextInfo, JwtClaims claimsSet) throws ParseException {
        NumericDate iat;
        NumericDate exp;

        try {
            iat = claimsSet.getIssuedAt();
            exp = claimsSet.getExpirationTime();
        } catch (Exception ex) {
            throw PrincipalMessages.msg.invalidIatExp();
        }

        if (iat.getValue() > exp.getValue()) {
            throw PrincipalMessages.msg.failedToVerifyIatExp(exp, iat);
        }
        final Long maxTimeToLiveSecs = authContextInfo.getMaxTimeToLiveSecs();

        if (maxTimeToLiveSecs != null) {
            if (exp.getValue() - iat.getValue() > maxTimeToLiveSecs) {
                throw PrincipalMessages.msg.expExceeded(exp, maxTimeToLiveSecs, iat);
            }
        } else {
            PrincipalLogging.log.noMaxTTLSpecified();
        }
    }

    private void verifyRequiredClaims(JWTAuthContextInfo authContextInfo, JwtContext jwtContext) throws InvalidJwtException {
        final Set<String> requiredClaims = authContextInfo.getRequiredClaims();

        if (requiredClaims != null) {
            if (!jwtContext.getJwtClaims().getClaimsMap().keySet().containsAll(requiredClaims)) {
                if (PrincipalLogging.log.isDebugEnabled()) {
                    final String missingClaims = requiredClaims.stream()
                            .filter(claim -> !jwtContext.getJwtClaims().getClaimsMap().containsKey(claim))
                            .collect(Collectors.joining(","));
                    PrincipalLogging.log.missingClaims(missingClaims);
                }
                throw PrincipalMessages.msg.missingClaims(s -> new InvalidJwtException(s, emptyList(), jwtContext));
            }
        }
    }

    protected VerificationKeyResolver getVerificationKeyResolver(JWTAuthContextInfo authContextInfo)
            throws UnresolvableKeyException {
        if (keyResolver == null) {
            synchronized (this) {
                if (keyResolver == null)
                    keyResolver = authContextInfo.isVerifyCertificateThumbprint()
                            ? new X509KeyLocationResolver(authContextInfo)
                            : new KeyLocationResolver(authContextInfo);
            }
        }
        return keyResolver;
    }

    protected DecryptionKeyResolver getDecryptionKeyResolver(JWTAuthContextInfo authContextInfo)
            throws UnresolvableKeyException {
        if (decryptionKeyResolver == null) {
            synchronized (this) {
                if (decryptionKeyResolver == null)
                    decryptionKeyResolver = new DecryptionKeyLocationResolver(authContextInfo);
            }
        }
        return decryptionKeyResolver;
    }

    protected ProtectionLevel getProtectionLevel(JWTAuthContextInfo authContextInfo) {
        if (authContextInfo.getDecryptionKeyLocation() != null
                || authContextInfo.getDecryptionKeyContent() != null
                || authContextInfo.getPrivateDecryptionKey() != null
                || authContextInfo.getSecretDecryptionKey() != null) {
            boolean sign = authContextInfo.getPublicVerificationKey() != null
                    || authContextInfo.getSecretVerificationKey() != null
                    || authContextInfo.getPublicKeyContent() != null
                    || authContextInfo.getPublicKeyLocation() != null;
            return sign ? ProtectionLevel.SIGN_ENCRYPT : ProtectionLevel.ENCRYPT;
        } else {
            return ProtectionLevel.SIGN;
        }
    }

    protected enum ProtectionLevel {
        SIGN,
        ENCRYPT,
        SIGN_ENCRYPT
    }
}
