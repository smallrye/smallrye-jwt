package io.smallrye.jwt.auth.cdi;

import jakarta.enterprise.util.AnnotationLiteral;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.Claims;

class ClaimQualifier extends AnnotationLiteral<Claim> implements Claim {
    private static final long serialVersionUID = 1L;
    private final String value;
    private final Claims standard;

    ClaimQualifier(String value, Claims standard) {
        this.value = value != null ? value : "";
        this.standard = standard != null ? standard : Claims.UNKNOWN;
    }

    @Override
    public String value() {
        return value;
    }

    @Override
    public Claims standard() {
        return standard;
    }
}
