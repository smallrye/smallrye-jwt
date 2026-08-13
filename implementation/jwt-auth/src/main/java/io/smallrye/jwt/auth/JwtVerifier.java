package io.smallrye.jwt.auth;

import java.security.Key;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.crypto.SecretKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ExpiredJWTException;

import io.smallrye.jwt.algorithm.EdDSAVerifier;
import io.smallrye.jwt.auth.principal.JsonWebSignatureImpl;
import io.smallrye.jwt.auth.principal.StandardClaimsVerifier;
import io.smallrye.jwt.common.JwtClaims;

/**
 * A builder-style JWT verifier that encapsulates parsing, key resolution,
 * signature verification, and claims validation.
 */
public class JwtVerifier {

    private final VerificationKeyResolver keyResolver;
    private final Set<String> allowedAlgorithms;
    private final Set<String> acceptedAudience;
    private final String expectedIssuer;
    private final Set<String> requiredClaims;
    private final int clockSkewSeconds;
    private final boolean relaxKeyValidation;
    private final boolean requireExpirationTime;
    private final boolean requireIssuedAt;
    private final List<ClaimsValidator> claimsValidators;

    private JwtVerifier(Builder builder) {
        this.keyResolver = builder.keyResolver;
        this.allowedAlgorithms = builder.allowedAlgorithms;
        this.acceptedAudience = builder.acceptedAudience;
        this.expectedIssuer = builder.expectedIssuer;
        this.requiredClaims = builder.requiredClaims;
        this.clockSkewSeconds = builder.clockSkewSeconds;
        this.relaxKeyValidation = builder.relaxKeyValidation;
        this.requireExpirationTime = builder.requireExpirationTime;
        this.requireIssuedAt = builder.requireIssuedAt;
        this.claimsValidators = builder.claimsValidators;
    }

    /**
     * Verify the token and return its verified claims together with the {@code typ} JOSE header value.
     * The token is decoded only once.
     */
    public JwtContext verify(String token) throws InvalidJWTException, UnresolvableKeyException {
        final SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(token);
        } catch (java.text.ParseException e) {
            // Nimbus throws java.text.ParseException when parsing a malformed token.
            throw new InvalidJWTException(e.getMessage());
        }

        try {
            String alg = signedJWT.getHeader().getAlgorithm().getName();

            if (!allowedAlgorithms.contains(alg)) {
                throw new InvalidJWTException("Algorithm " + alg + " is not allowed");
            }

            Key verificationKey = keyResolver.resolveKey(new JsonWebSignatureImpl(signedJWT, token));

            if (!relaxKeyValidation && verificationKey instanceof RSAPublicKey) {
                int bitLength = ((RSAPublicKey) verificationKey).getModulus().bitLength();
                if (bitLength < 2048) {
                    throw new InvalidJWTException("RSA key size must be at least 2048 bits, got " + bitLength);
                }
            }

            JWSVerifier verifier = createVerifier(verificationKey, signedJWT.getHeader().getAlgorithm());
            if (!signedJWT.verify(verifier)) {
                // Nimbus signals a failed signature by returning false rather than throwing.
                throw new InvalidJWTException("Token signature is invalid");
            }

            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

            // Build complete required claims set
            Set<String> required = requiredClaims != null ? new HashSet<>(requiredClaims) : new HashSet<>();
            if (requireExpirationTime) {
                required.add(JWTClaimNames.EXPIRATION_TIME);
            }
            if (requireIssuedAt) {
                required.add(JWTClaimNames.ISSUED_AT);
            }

            // Delegate standard claims validation
            StandardClaimsVerifier.builder()
                    .audience(acceptedAudience)
                    .issuer(expectedIssuer)
                    .requiredClaims(required)
                    .clockSkewSeconds(clockSkewSeconds)
                    .build()
                    .verify(claimsSet);

            JwtClaims claims = new JwtClaims(claimsSet.getClaims());

            // Run custom validators
            ClaimsValidator.VerificationContext context = new ClaimsValidator.VerificationContext(claims);
            for (ClaimsValidator validator : claimsValidators) {
                String error = validator.validate(context);
                if (error != null) {
                    throw new InvalidJWTException(error);
                }
            }

            JOSEObjectType type = signedJWT.getHeader().getType();

            return new JwtContext(type != null ? type.toString() : null, claims);
        } catch (ExpiredJWTException e) {
            // Nimbus signals expiry with ExpiredJWTException.
            throw new TokenExpiredException(e.getMessage());
        } catch (java.text.ParseException | BadJOSEException e) {
            // Nimbus reports a malformed token via java.text.ParseException and a failed standard
            // claims check via BadJOSEException.
            throw new InvalidJWTException(e.getMessage());
        } catch (JOSEException e) {
            // Nimbus reports a cryptographic failure via JOSEException; keep it as the cause for debugging.
            throw new InvalidJWTException(e.getMessage(), e);
        }
    }

    public static JWSVerifier createVerifier(Key key, JWSAlgorithm alg) throws JOSEException {
        if (key instanceof RSAPublicKey) {
            return new RSASSAVerifier((RSAPublicKey) key);
        } else if (key instanceof ECPublicKey) {
            return new ECDSAVerifier((ECPublicKey) key);
        } else if (key instanceof SecretKey) {
            return new MACVerifier((SecretKey) key);
        } else if (key instanceof EdECPublicKey) {
            return new EdDSAVerifier((PublicKey) key);
        }
        throw new JOSEException("Unsupported key type for verification: " + key.getClass().getName());
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private VerificationKeyResolver keyResolver;
        private Set<String> allowedAlgorithms;
        private Set<String> acceptedAudience;
        private String expectedIssuer;
        private final Set<String> requiredClaims = new HashSet<>();
        private int clockSkewSeconds;
        private boolean relaxKeyValidation;
        private boolean requireExpirationTime = true;
        private boolean requireIssuedAt = true;
        private final List<ClaimsValidator> claimsValidators = new ArrayList<>();

        public Builder verificationKeyResolver(VerificationKeyResolver resolver) {
            this.keyResolver = resolver;
            return this;
        }

        public Builder allowedAlgorithms(Set<String> algorithms) {
            this.allowedAlgorithms = algorithms;
            return this;
        }

        public Builder expectedIssuer(String issuer) {
            this.expectedIssuer = issuer;
            return this;
        }

        public Builder expectedAudience(String... audience) {
            this.acceptedAudience = Set.of(audience);
            return this;
        }

        public Builder requireExpirationTime() {
            this.requiredClaims.add(JWTClaimNames.EXPIRATION_TIME);
            return this;
        }

        public Builder requireExpirationTime(boolean require) {
            this.requireExpirationTime = require;
            return this;
        }

        public Builder requireIssuedAt(boolean require) {
            this.requireIssuedAt = require;
            return this;
        }

        public Builder requireSubject() {
            this.requiredClaims.add(JWTClaimNames.SUBJECT);
            return this;
        }

        public Builder requiredClaims(Set<String> claims) {
            if (claims != null) {
                this.requiredClaims.addAll(claims);
            }
            return this;
        }

        public Builder clockSkewSeconds(int seconds) {
            this.clockSkewSeconds = seconds;
            return this;
        }

        public Builder relaxKeyValidation() {
            this.relaxKeyValidation = true;
            return this;
        }

        public Builder claimsValidator(ClaimsValidator validator) {
            this.claimsValidators.add(validator);
            return this;
        }

        public Builder claimsValidators(List<ClaimsValidator> validators) {
            this.claimsValidators.addAll(validators);
            return this;
        }

        public JwtVerifier build() {
            if (keyResolver == null) {
                throw new IllegalStateException("VerificationKeyResolver is required");
            }
            if (allowedAlgorithms == null || allowedAlgorithms.isEmpty()) {
                throw new IllegalStateException("At least one allowed algorithm is required");
            }
            return new JwtVerifier(this);
        }
    }
}
