package io.smallrye.jwt.auth.principal;

import static java.lang.String.format;

import java.util.Objects;
import java.util.stream.Stream;

import org.eclipse.microprofile.jwt.Claims;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.ErrorCodeValidator;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.JwtContext;

public class CustomSubValidator implements ErrorCodeValidator {
    private JWTAuthContextInfo authContextInfo;

    public CustomSubValidator(JWTAuthContextInfo authContextInfo) {
        this.authContextInfo = authContextInfo;
    }

    @Override
    public Error validate(JwtContext jwtContext) throws MalformedClaimException {
        if (!authContextInfo.isRequireNamedPrincipal()) {
            return null;
        }

        JwtClaims jwtClaims = jwtContext.getJwtClaims();

        if (authContextInfo.getSubPath() != null) {
            final String subPathClaimValue = ClaimSubPathResolver.checkSubPath(authContextInfo, jwtClaims);
            if (subPathClaimValue == null) {
                return new Error(ErrorCodes.SUBJECT_MISSING,
                        format("No Subject (%s) claim is present.", authContextInfo.getSubPath()));
            }
        } else if (authContextInfo.getDefaultSubClaim() != null) {
            String subject = jwtClaims.getClaimValue(authContextInfo.getDefaultSubClaim(), String.class);
            if (subject == null) {
                return new Error(ErrorCodes.SUBJECT_MISSING,
                        format("No Subject (%s) claim is present.", authContextInfo.getDefaultSubClaim()));
            }
        } else {
            boolean hasDefaultPrincipalClaim = Stream.of(Claims.sub.name(), Claims.upn.name(), Claims.preferred_username.name())
                    .map(jwtClaims::getClaimValue)
                    .anyMatch(Objects::nonNull);
            if (!hasDefaultPrincipalClaim) {
                return new Error(ErrorCodes.SUBJECT_MISSING, "No Subject claim is present.");
            }
        }

        return null;
    }
}
