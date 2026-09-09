package io.smallrye.jwt.auth.principal;

import java.util.Set;

import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;

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

    public void verify(JWTClaimsSet claimsSet) throws BadJOSEException {
        JWTClaimsSet exactMatchClaims = issuer != null ? new JWTClaimsSet.Builder().issuer(issuer).build() : null;
        DefaultJWTClaimsVerifier<?> verifier = new DefaultJWTClaimsVerifier<>(
                acceptedAudience, exactMatchClaims, requiredClaims, null);
        verifier.setMaxClockSkew(clockSkewSeconds);
        verifier.verify(claimsSet, null);
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
