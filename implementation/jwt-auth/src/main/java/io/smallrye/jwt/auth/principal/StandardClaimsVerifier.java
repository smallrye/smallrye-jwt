package io.smallrye.jwt.auth.principal;

import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.ExpiredJWTException;

import io.smallrye.jwt.auth.InvalidJWTException;
import io.smallrye.jwt.auth.TokenExpiredException;

/**
 * Verifies standard JWT claims (issuer, audience, exp, iat, required claims) using Nimbus.
 */
public class StandardClaimsVerifier {
    private final Set<String> acceptedAudience;
    private final String issuer;
    private final Set<String> requiredClaims;
    private final int clockSkewSeconds;

    private StandardClaimsVerifier(Builder builder) {
        this.acceptedAudience = builder.acceptedAudience;
        this.issuer = builder.issuer;
        this.requiredClaims = builder.requiredClaims;
        this.clockSkewSeconds = builder.clockSkewSeconds;
    }

    // Nimbus converts the numeric date claims to java.util.Date with 'seconds * 1000', so larger values overflow
    private static final long MAX_NUMERIC_DATE_SECONDS = Long.MAX_VALUE / 1000;

    /**
     * Parse the JWT claims JSON. Unlike {@link JWTClaimsSet#parse(String)}, a numeric 'sub' claim is rejected,
     * as RFC 7519 requires it to be a string and jose4j rejected it before the migration to Nimbus JOSE+JWT.
     * The 'exp', 'nbf' and 'iat' claims are also rejected if their values can not be converted to milliseconds
     * without overflow, which would otherwise turn a long expired token into a valid one.
     */
    public static JWTClaimsSet parseClaimsSet(String json) throws ParseException {
        Map<String, Object> claims = JSONObjectUtils.parse(json);
        Object sub = claims.get(JWTClaimNames.SUBJECT);
        if (sub != null && !(sub instanceof String)) {
            throw new ParseException("The \"sub\" claim must be a string", 0);
        }
        for (String name : List.of(JWTClaimNames.EXPIRATION_TIME, JWTClaimNames.NOT_BEFORE, JWTClaimNames.ISSUED_AT)) {
            if (claims.get(name) instanceof Number number
                    && Math.abs(number.longValue()) > MAX_NUMERIC_DATE_SECONDS) {
                throw new ParseException("The \"" + name + "\" claim value is out of range", 0);
            }
        }
        return JWTClaimsSet.parse(claims);
    }

    public void verify(JWTClaimsSet claimsSet) throws InvalidJWTException {
        JWTClaimsSet exactMatchClaims = issuer != null ? new JWTClaimsSet.Builder().issuer(issuer).build() : null;
        DefaultJWTClaimsVerifier<?> verifier = new DefaultJWTClaimsVerifier<>(
                acceptedAudience, exactMatchClaims, requiredClaims, null);
        verifier.setMaxClockSkew(clockSkewSeconds);
        try {
            verifier.verify(claimsSet, null);
        } catch (ExpiredJWTException ex) {
            // Nimbus signals expiry with ExpiredJWTException.
            throw new TokenExpiredException(ex.getMessage());
        } catch (BadJOSEException ex) {
            logMissingClaims(claimsSet);
            throw new InvalidJWTException(ex.getMessage());
        }
        verifyExpirationTimeConsistency(claimsSet);
    }

    // As in jose4j NumericDateValidator, 'exp' can not be before 'iat' or 'nbf'; Nimbus does not check it
    private static void verifyExpirationTimeConsistency(JWTClaimsSet claimsSet) throws InvalidJWTException {
        Date exp = claimsSet.getExpirationTime();
        if (exp == null) {
            return;
        }
        Date iat = claimsSet.getIssueTime();
        if (iat != null && exp.before(iat)) {
            throw PrincipalMessages.msg.failedToVerifyIatExp(toSeconds(exp), toSeconds(iat));
        }
        Date nbf = claimsSet.getNotBeforeTime();
        if (nbf != null && exp.before(nbf)) {
            throw PrincipalMessages.msg.failedToVerifyNbfExp(toSeconds(exp), toSeconds(nbf));
        }
    }

    private static long toSeconds(Date date) {
        return date.getTime() / 1000;
    }

    private void logMissingClaims(JWTClaimsSet claimsSet) {
        if (requiredClaims != null && PrincipalLogging.log.isDebugEnabled()) {
            String missing = requiredClaims.stream()
                    .filter(claim -> !claimsSet.getClaims().containsKey(claim))
                    .sorted()
                    .collect(Collectors.joining(","));
            if (!missing.isEmpty()) {
                PrincipalLogging.log.missingClaims(missing);
            }
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private Set<String> acceptedAudience;
        private String issuer;
        private Set<String> requiredClaims;
        private int clockSkewSeconds;

        public Builder audience(Set<String> audience) {
            this.acceptedAudience = audience;
            return this;
        }

        public Builder issuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        public Builder requiredClaims(Set<String> claims) {
            this.requiredClaims = claims;
            return this;
        }

        public Builder clockSkewSeconds(int seconds) {
            this.clockSkewSeconds = seconds;
            return this;
        }

        public StandardClaimsVerifier build() {
            return new StandardClaimsVerifier(this);
        }
    }
}
