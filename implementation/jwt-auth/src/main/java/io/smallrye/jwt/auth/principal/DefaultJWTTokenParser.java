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

import java.security.Key;
import java.util.HashSet;
import java.util.Set;

import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;

import io.smallrye.jwe.JsonWebEncryption;
import io.smallrye.jwe.JweDecrypter;
import io.smallrye.jwe.JweException;
import io.smallrye.jwt.KeyProvider;
import io.smallrye.jwt.auth.DecryptionKeyResolver;
import io.smallrye.jwt.auth.InvalidJWTException;
import io.smallrye.jwt.auth.JwtContext;
import io.smallrye.jwt.auth.JwtVerifier;
import io.smallrye.jwt.auth.SingleKeyVerificationKeyResolver;
import io.smallrye.jwt.auth.TokenExpiredException;
import io.smallrye.jwt.auth.UnresolvableKeyException;
import io.smallrye.jwt.auth.VerificationKeyResolver;
import io.smallrye.jwt.common.JwtClaims;

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
            JsonWebEncryption jwe = JsonWebEncryption.parse(token);

            // the key encryption algorithm is checked by JweDecrypter
            if (!"JWT".equals(jwe.headers().contentType())) {
                PrincipalLogging.log.encryptedTokenMissingContentType();
                throw PrincipalMessages.msg.encryptedTokenMissingContentType();
            }

            Key decryptionKey = getDecryptionKey(jwe, authContextInfo);

            return JweDecrypter.builder(decryptionKey)
                    .keyAlgorithms(authContextInfo.getKeyEncryptionAlgorithm())
                    .build()
                    .decrypt(jwe);
        } catch (UnresolvableKeyException e) {
            PrincipalLogging.log.decryptionKeyUnresolvable();
            throw PrincipalMessages.msg.decryptionKeyUnresolvable(e);
        } catch (JweException e) {
            // The token is either malformed or can not be decrypted; keep the cause for debugging.
            PrincipalLogging.log.encryptedTokenSequenceInvalid();
            throw PrincipalMessages.msg.encryptedTokenSequenceInvalid(new InvalidJWTException(e.getMessage(), e));
        }
    }

    private JwtContext parseClaims(String token, JWTAuthContextInfo authContextInfo, ProtectionLevel level)
            throws ParseException {
        try {
            JwtContext context;

            if (level == ProtectionLevel.SIGN) {
                // Signature verification (algorithm check, key resolution/validation, signature
                // and standard claims) is delegated to the shared JwtVerifier.
                JwtVerifier verifier = buildVerifier(authContextInfo);
                context = verifier.verify(token);
            } else {
                JsonWebEncryption jwe = JsonWebEncryption.parse(token);
                String type = jwe.headers().type();

                Key decryptionKey;
                try {
                    decryptionKey = getDecryptionKey(jwe, authContextInfo);
                } catch (UnresolvableKeyException e) {
                    PrincipalLogging.log.decryptionKeyUnresolvable();
                    throw PrincipalMessages.msg.decryptionKeyUnresolvable(e);
                }

                JWTClaimsSet claimsSet = StandardClaimsVerifier
                        .parseClaimsSet(JweDecrypter.builder(decryptionKey)
                                .keyAlgorithms(authContextInfo.getKeyEncryptionAlgorithm())
                                .build()
                                .decrypt(jwe));

                verifyDecryptedStandardClaims(authContextInfo, claimsSet);

                context = new JwtContext(type, claimsSetToMap(claimsSet));
            }

            JwtClaims claimsMap = context.claims();

            // Note: 'exp', 'iat' (if needed), 'nbf', the exp/iat/nbf consistency and the additional required
            // claims are validated by StandardClaimsVerifier

            if (isIssuedAtRequired(authContextInfo)) {
                verifyIatAndExpAndTimeToLive(authContextInfo, claimsMap);
            }

            PrincipalUtils.setClaims(claimsMap, token, authContextInfo);

            if (authContextInfo.isRequireNamedPrincipal()) {
                checkNameClaims(claimsMap);
            }

            return context;
        } catch (ParseException e) {
            throw e;
        } catch (UnresolvableKeyException e) {
            PrincipalLogging.log.verificationKeyUnresolvable();
            throw PrincipalMessages.msg.failedToVerifyToken(e);
        } catch (InvalidJWTException e) {
            // SmallRye typed cause passes straight through.
            PrincipalLogging.log.tokenInvalid();
            throw PrincipalMessages.msg.failedToVerifyToken(e);
        } catch (java.text.ParseException e) {
            // Nimbus reports a malformed token via java.text.ParseException.
            PrincipalLogging.log.tokenInvalid();
            throw PrincipalMessages.msg.failedToVerifyToken(new InvalidJWTException(e.getMessage()));
        } catch (JweException e) {
            // The token can not be decrypted; keep the cause for debugging.
            PrincipalLogging.log.tokenInvalid();
            throw PrincipalMessages.msg.failedToVerifyToken(new InvalidJWTException(e.getMessage(), e));
        }
    }

    private JwtClaims claimsSetToMap(JWTClaimsSet claimsSet) {
        return new JwtClaims(claimsSet.getClaims());
    }

    private boolean isIssuedAtRequired(JWTAuthContextInfo authContextInfo) {
        return authContextInfo.getMaxTimeToLiveSecs() == null
                || authContextInfo.getMaxTimeToLiveSecs() > 0 || authContextInfo.getTokenAge() != null;
    }

    private static int getClockSkew(JWTAuthContextInfo authContextInfo) {
        // the exp grace period, if set, takes precedence over the clock skew
        if (authContextInfo.getExpGracePeriodSecs() > 0) {
            return authContextInfo.getExpGracePeriodSecs();
        }
        return Math.max(authContextInfo.getClockSkew(), 0);
    }

    private JwtVerifier buildVerifier(JWTAuthContextInfo authContextInfo) throws UnresolvableKeyException {
        int clockSkew = getClockSkew(authContextInfo);
        boolean issuedAtRequired = isIssuedAtRequired(authContextInfo);

        // Direct verification keys take precedence over the configured key resolver
        VerificationKeyResolver resolver;
        if (authContextInfo.getPublicVerificationKey() != null) {
            resolver = new SingleKeyVerificationKeyResolver(authContextInfo.getPublicVerificationKey());
        } else if (authContextInfo.getSecretVerificationKey() != null) {
            resolver = new SingleKeyVerificationKeyResolver(authContextInfo.getSecretVerificationKey());
        } else {
            resolver = getVerificationKeyResolver(authContextInfo);
        }

        JwtVerifier.Builder builder = JwtVerifier.builder()
                .verificationKeyResolver(resolver)
                .allowedAlgorithms(authContextInfo.getSignatureAlgorithm())
                .clockSkewSeconds(clockSkew)
                .requiredClaims(authContextInfo.getRequiredClaims())
                .requireExpirationTime(true)
                .requireIssuedAt(issuedAtRequired);

        if (authContextInfo.isRelaxVerificationKeyValidation()) {
            builder.relaxKeyValidation();
        }
        if (authContextInfo.getIssuedBy() != null) {
            builder.expectedIssuer(authContextInfo.getIssuedBy());
        }
        if (authContextInfo.getExpectedAudience() != null) {
            builder.expectedAudience(authContextInfo.getExpectedAudience().toArray(new String[0]));
        }
        return builder.build();
    }

    private void verifyDecryptedStandardClaims(JWTAuthContextInfo authContextInfo, JWTClaimsSet claimsSet)
            throws InvalidJWTException {
        Set<String> required = authContextInfo.getRequiredClaims() != null
                ? new HashSet<>(authContextInfo.getRequiredClaims())
                : new HashSet<>();
        required.add(JWTClaimNames.EXPIRATION_TIME);
        if (isIssuedAtRequired(authContextInfo)) {
            required.add(JWTClaimNames.ISSUED_AT);
        }

        StandardClaimsVerifier.builder()
                .audience(authContextInfo.getExpectedAudience())
                .issuer(authContextInfo.getIssuedBy())
                .requiredClaims(required)
                .clockSkewSeconds(getClockSkew(authContextInfo))
                .build()
                .verify(claimsSet);
    }

    private void checkNameClaims(JwtClaims claims) throws InvalidJWTException {
        final boolean hasPrincipalClaim = claims.getSubject() != null ||
                claims.getUpn() != null ||
                claims.getPreferredUsername() != null;

        if (!hasPrincipalClaim) {
            throw PrincipalMessages.msg.claimNotFound(InvalidJWTException::new);
        }
    }

    private void verifyIatAndExpAndTimeToLive(JWTAuthContextInfo authContextInfo, JwtClaims claims)
            throws ParseException {
        Long iat = claims.getIssuedAt();
        Long exp = claims.getExpirationTime();

        if (iat == null || exp == null) {
            throw PrincipalMessages.msg.invalidIatExp();
        }

        final Long maxTimeToLiveSecs = authContextInfo.getMaxTimeToLiveSecs();

        if (maxTimeToLiveSecs != null) {
            if (exp - iat > maxTimeToLiveSecs) {
                throw PrincipalMessages.msg.expExceeded(exp, maxTimeToLiveSecs, iat);
            }
        }

        final Long tokenAge = authContextInfo.getTokenAge();

        if (tokenAge != null) {
            long now = System.currentTimeMillis() / 1000;
            if (now - iat > tokenAge) {
                // A token that is too old is stale rather than structurally invalid, so it is
                // reported as expired to let callers trigger a token refresh.
                throw PrincipalMessages.msg.tokenAgeExceeded(tokenAge, new TokenExpiredException("Token age exceeded"));
            }
        }
    }

    private Key getDecryptionKey(JsonWebEncryption jwe, JWTAuthContextInfo authContextInfo)
            throws UnresolvableKeyException {
        if (authContextInfo.getPrivateDecryptionKey() != null) {
            return authContextInfo.getPrivateDecryptionKey();
        } else if (authContextInfo.getSecretDecryptionKey() != null) {
            return authContextInfo.getSecretDecryptionKey();
        }
        return resolveDecryptionKey(jwe, authContextInfo);
    }

    private Key resolveDecryptionKey(JsonWebEncryption jwe, JWTAuthContextInfo authContextInfo)
            throws UnresolvableKeyException {
        return getDecryptionKeyResolver(authContextInfo).resolveKey(jwe);
    }

    protected VerificationKeyResolver getVerificationKeyResolver(JWTAuthContextInfo authContextInfo)
            throws UnresolvableKeyException {
        if (keyResolver == null) {
            synchronized (this) {
                if (keyResolver == null) {
                    if (KeyProvider.AWS_ALB == authContextInfo.getKeyProvider()) {
                        keyResolver = new AwsAlbKeyResolver(authContextInfo);
                    } else if (authContextInfo.isVerifyCertificateThumbprint()) {
                        keyResolver = new X509KeyLocationResolver(authContextInfo);
                    } else {
                        keyResolver = new KeyLocationResolver(authContextInfo);
                    }
                }
            }
        }
        return keyResolver;
    }

    protected DecryptionKeyResolver getDecryptionKeyResolver(JWTAuthContextInfo authContextInfo)
            throws UnresolvableKeyException {
        if (decryptionKeyResolver == null) {
            synchronized (this) {
                if (decryptionKeyResolver == null) {
                    decryptionKeyResolver = new DecryptionKeyLocationResolver(authContextInfo);
                }
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
