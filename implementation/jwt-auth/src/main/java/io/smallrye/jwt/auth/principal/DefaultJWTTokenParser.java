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

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.XECPrivateKey;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.AESDecrypter;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.PasswordBasedDecrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ExpiredJWTException;

import io.smallrye.jwt.KeyProvider;
import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.algorithm.XDHDecrypter;
import io.smallrye.jwt.auth.DecryptionKeyResolver;
import io.smallrye.jwt.auth.InvalidJWTException;
import io.smallrye.jwt.auth.JwtContext;
import io.smallrye.jwt.auth.JwtVerifier;
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
            JWEObject jwe = JWEObject.parse(token);

            String alg = jwe.getHeader().getAlgorithm().getName();
            verifyEncryptionAlgorithm(alg, authContextInfo);

            if (!"JWT".equals(jwe.getHeader().getContentType())) {
                PrincipalLogging.log.encryptedTokenMissingContentType();
                throw PrincipalMessages.msg.encryptedTokenMissingContentType();
            }

            Key decryptionKey;
            if (authContextInfo.getPrivateDecryptionKey() != null) {
                decryptionKey = authContextInfo.getPrivateDecryptionKey();
            } else if (authContextInfo.getSecretDecryptionKey() != null) {
                decryptionKey = authContextInfo.getSecretDecryptionKey();
            } else {
                decryptionKey = resolveDecryptionKey(jwe, token, authContextInfo);
            }

            JWEDecrypter decrypter = createDecrypter(decryptionKey, alg);
            jwe.decrypt(decrypter);

            return jwe.getPayload().toString();
        } catch (UnresolvableKeyException e) {
            PrincipalLogging.log.decryptionKeyUnresolvable();
            throw PrincipalMessages.msg.decryptionKeyUnresolvable(e);
        } catch (java.text.ParseException e) {
            // Nimbus reports a malformed token via java.text.ParseException.
            PrincipalLogging.log.encryptedTokenSequenceInvalid();
            throw PrincipalMessages.msg.encryptedTokenSequenceInvalid(new InvalidJWTException(e.getMessage()));
        } catch (JOSEException e) {
            // Nimbus reports a cryptographic failure via JOSEException; keep it as the cause for debugging.
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
                EncryptedJWT encryptedJWT = EncryptedJWT.parse(token);
                JOSEObjectType type = encryptedJWT.getHeader().getType();
                String alg = encryptedJWT.getHeader().getAlgorithm().getName();

                verifyEncryptionAlgorithm(alg, authContextInfo);

                Key decryptionKey;
                if (authContextInfo.getPrivateDecryptionKey() != null) {
                    decryptionKey = authContextInfo.getPrivateDecryptionKey();
                } else if (authContextInfo.getSecretDecryptionKey() != null) {
                    decryptionKey = authContextInfo.getSecretDecryptionKey();
                } else {
                    decryptionKey = resolveDecryptionKey(encryptedJWT, token, authContextInfo);
                }

                JWEDecrypter decrypter = createDecrypter(decryptionKey, alg);
                encryptedJWT.decrypt(decrypter);

                JWTClaimsSet claimsSet = encryptedJWT.getJWTClaimsSet();

                // Verify standard claims for decrypted token
                int clockSkew = Math.max(authContextInfo.getExpGracePeriodSecs(), authContextInfo.getClockSkew());
                boolean issuedAtRequired = isIssuedAtRequired(authContextInfo);

                Set<String> required = authContextInfo.getRequiredClaims() != null
                        ? new HashSet<>(authContextInfo.getRequiredClaims())
                        : new HashSet<>();
                required.add(JWTClaimNames.EXPIRATION_TIME);
                if (issuedAtRequired) {
                    required.add(JWTClaimNames.ISSUED_AT);
                }

                StandardClaimsVerifier.builder()
                        .audience(authContextInfo.getExpectedAudience())
                        .issuer(authContextInfo.getIssuedBy())
                        .requiredClaims(required)
                        .clockSkewSeconds(clockSkew)
                        .build()
                        .verify(claimsSet);

                context = new JwtContext(type != null ? type.toString() : null, claimsSetToMap(claimsSet));
            }

            JwtClaims claimsMap = context.claims();

            // Note: 'exp', 'iat' (if needed), and additional required claims are validated by DefaultJWTClaimsVerifier

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
        } catch (ExpiredJWTException e) {
            // Nimbus signals expiry with ExpiredJWTException.
            PrincipalLogging.log.tokenInvalid();
            throw PrincipalMessages.msg.failedToVerifyToken(new TokenExpiredException(e.getMessage()));
        } catch (java.text.ParseException | BadJOSEException e) {
            // Nimbus reports a malformed token via java.text.ParseException and a failed standard
            // claims check via BadJOSEException.
            PrincipalLogging.log.tokenInvalid();
            throw PrincipalMessages.msg.failedToVerifyToken(new InvalidJWTException(e.getMessage()));
        } catch (JOSEException e) {
            // Nimbus reports a cryptographic failure via JOSEException; keep it as the cause for debugging.
            PrincipalLogging.log.tokenInvalid();
            throw PrincipalMessages.msg.failedToVerifyToken(new InvalidJWTException(e.getMessage(), e));
        } catch (Exception e) {
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

    private JwtVerifier buildVerifier(JWTAuthContextInfo authContextInfo) throws UnresolvableKeyException {
        Set<String> allowedAlgs = authContextInfo.getSignatureAlgorithm().stream()
                .map(SignatureAlgorithm::getAlgorithm)
                .collect(Collectors.toSet());

        int clockSkew = Math.max(authContextInfo.getExpGracePeriodSecs(), authContextInfo.getClockSkew());
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
                .allowedAlgorithms(allowedAlgs)
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

    private void verifyEncryptionAlgorithm(String alg, JWTAuthContextInfo authContextInfo) throws ParseException {
        Set<String> allowedAlgs = authContextInfo.getKeyEncryptionAlgorithm().stream()
                .map(KeyEncryptionAlgorithm::getAlgorithm)
                .collect(Collectors.toSet());
        if (!allowedAlgs.contains(alg)) {
            throw PrincipalMessages.msg.failedToVerifyToken(
                    new InvalidJWTException("Key encryption algorithm " + alg + " is not allowed"));
        }
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

        if (iat > exp) {
            throw PrincipalMessages.msg.failedToVerifyIatExp(exp, iat);
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

    private JWEDecrypter createDecrypter(Key key, String algorithm) throws JOSEException {
        if (key instanceof RSAPrivateKey) {
            return new RSADecrypter((RSAPrivateKey) key);
        } else if (key instanceof ECPrivateKey) {
            return new ECDHDecrypter((ECPrivateKey) key);
        } else if (key instanceof SecretKey) {
            SecretKey secretKey = (SecretKey) key;
            if ("dir".equals(algorithm)) {
                return new DirectDecrypter(secretKey);
            }
            if (algorithm != null && algorithm.startsWith("PBES2")) {
                String password = new String(secretKey.getEncoded(), StandardCharsets.UTF_8);
                return new PasswordBasedDecrypter(password);
            }
            return new AESDecrypter(secretKey);
        } else if (key instanceof XECPrivateKey) {
            return XDHDecrypter.fromXECPrivateKey((XECPrivateKey) key);
        }
        throw new JOSEException("Unsupported key type for decryption: " + key.getClass().getName());
    }

    private Key resolveDecryptionKey(JWEObject jweObject, String token, JWTAuthContextInfo authContextInfo)
            throws UnresolvableKeyException, ParseException {
        return getDecryptionKeyResolver(authContextInfo).resolveKey(new JsonWebEncryptionImpl(jweObject, token));
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
