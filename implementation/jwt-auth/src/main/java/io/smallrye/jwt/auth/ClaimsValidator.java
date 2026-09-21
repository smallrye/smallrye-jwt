package io.smallrye.jwt.auth;

import io.smallrye.jwt.common.JwtClaims;

/**
 * Interface for custom JWT claims validation.
 * Implementations validate claims and return null on success or an error message on failure.
 */
public interface ClaimsValidator {
    /**
     * Validation context containing claims and potentially additional information.
     */
    record VerificationContext(JwtClaims claims) {
    }

    /**
     * Validate the given JWT claims.
     *
     * @param context the verification context containing claims
     * @return null if valid, an error description string if invalid
     */
    String validate(VerificationContext context);
}
