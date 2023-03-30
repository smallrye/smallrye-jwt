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

import java.util.HashSet;
import java.util.Set;
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

import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;

/**
 * Default JWT token validator
 *
 */
public class DefaultJWTTokenParser {

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
                            encryptionAlgorithms(authContextInfo)));
            if (authContextInfo.getPrivateDecryptionKey() != null) {
                jwe.setKey(authContextInfo.getPrivateDecryptionKey());
            } else if (authContextInfo.getSecretDecryptionKey() != null) {
                jwe.setKey(authContextInfo.getSecretDecryptionKey());
            } else {
                jwe.setKey(getDecryptionKeyResolver(authContextInfo).resolveKey(jwe, null));
            }
            jwe.setCompactSerialization(token);
            if (!"JWT".equals(jwe.getContentTypeHeaderValue())) {
                PrincipalLogging.log.encryptedTokenMissingContentType();
                throw PrincipalMessages.msg.encryptedTokenMissingContentType();
            }
            return jwe.getPlaintextString();
        } catch (UnresolvableKeyException e) {
            PrincipalLogging.log.decryptionKeyUnresolvable();
            throw PrincipalMessages.msg.decryptionKeyUnresolvable(e);
        } catch (JoseException e) {
            PrincipalLogging.log.encryptedTokenSequenceInvalid();
            throw PrincipalMessages.msg.encryptedTokenSequenceInvalid(e);
        }
    }

    private String[] encryptionAlgorithms(JWTAuthContextInfo authContextInfo) {
        Set<String> algorithms = new HashSet<>();
        for (KeyEncryptionAlgorithm keyEncAlgo : authContextInfo.getKeyEncryptionAlgorithm()) {
            algorithms.add(keyEncAlgo.getAlgorithm());
        }
        return algorithms.toArray(new String[] {});
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
                                encryptionAlgorithms(authContextInfo)));
            }

            builder.setRequireExpirationTime();

            final boolean issuedAtRequired = authContextInfo.getMaxTimeToLiveSecs() == null
                    || authContextInfo.getMaxTimeToLiveSecs() > 0 || authContextInfo.getTokenAge() != null;
            if (issuedAtRequired) {
                builder.setRequireIssuedAt();
            }

            if (authContextInfo.getIssuedBy() != null) {
                builder.setExpectedIssuer(authContextInfo.getIssuedBy());
            }

            if (authContextInfo.getExpGracePeriodSecs() > 0) {
                builder.setAllowedClockSkewInSeconds(authContextInfo.getExpGracePeriodSecs());
            } else if (authContextInfo.getClockSkew() > 0) {
                builder.setAllowedClockSkewInSeconds(authContextInfo.getClockSkew());
            }

            setExpectedAudience(builder, authContextInfo);

            if (authContextInfo.isRelaxVerificationKeyValidation()) {
                builder.setRelaxVerificationKeyValidation();
            }
            JwtConsumer jwtConsumer = builder.build();

            //  Validate the JWT and process it to the Claims
            JwtContext jwtContext = jwtConsumer.process(token);
            JwtClaims claimsSet = jwtContext.getJwtClaims();

            if (issuedAtRequired) {
                verifyIatAndExpAndTimeToLive(authContextInfo, claimsSet);
            }
            verifyRequiredClaims(authContextInfo, jwtContext);

            PrincipalUtils.setClaims(claimsSet, token, authContextInfo);

            if (authContextInfo.isRequireNamedPrincipal()) {
                checkNameClaims(jwtContext);
            }

            return jwtContext;
        } catch (InvalidJwtException e) {
            if (e.getCause() instanceof UnresolvableKeyException) {
                PrincipalLogging.log.verificationKeyUnresolvable();
                throw PrincipalMessages.msg.failedToVerifyToken(e.getCause());
            } else {
                PrincipalLogging.log.tokenInvalid();
                throw PrincipalMessages.msg.failedToVerifyToken(e);
            }
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
        }

        final Long tokenAge = authContextInfo.getTokenAge();

        if (tokenAge != null) {
            long now = System.currentTimeMillis() / 1000;
            if (now - iat.getValue() > tokenAge) {
                throw PrincipalMessages.msg.tokenAgeExceeded(tokenAge);
            }
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
