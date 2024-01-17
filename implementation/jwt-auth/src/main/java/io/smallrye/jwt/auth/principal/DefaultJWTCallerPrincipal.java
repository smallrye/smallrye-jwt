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
 */
package io.smallrye.jwt.auth.principal;

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.eclipse.microprofile.jwt.Claims;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;

import io.smallrye.jwt.JsonUtils;

/**
 * A default implementation of JWTCallerPrincipal that wraps the jose4j JwtClaims.
 *
 * @see JwtClaims
 */
public class DefaultJWTCallerPrincipal extends JWTCallerPrincipal {
    private final JwtClaims claimsSet;

    /**
     * Create the DefaultJWTCallerPrincipal from the parsed JWT token and the extracted principal name
     *
     * @param rawToken - raw token value
     * @param tokenType - token type
     * @param claimsSet - Jose4J claims set
     */
    public DefaultJWTCallerPrincipal(String rawToken, String tokenType, JwtClaims claimsSet) {
        super(rawToken, tokenType);
        this.claimsSet = claimsSet;
        fixJoseTypes();
    }

    public DefaultJWTCallerPrincipal(String tokenType, JwtClaims claimsSet) {
        this(getRawToken(claimsSet), tokenType, claimsSet);
    }

    public DefaultJWTCallerPrincipal(JwtClaims claimsSet) {
        this("JWT", claimsSet);
    }

    protected static String getRawToken(JwtClaims claimsSet) {
        Object rawToken = claimsSet.getClaimValue(Claims.raw_token.name());
        return rawToken != null ? rawToken.toString() : null;
    }

    @Override
    public Set<String> getAudience() {
        Set<String> audSet = null;
        if (claimsSet.hasAudience()) {
            try {
                // Use LinkedHashSet to preserve iteration order
                audSet = new LinkedHashSet<>(claimsSet.getAudience());
            } catch (MalformedClaimException e) {
                PrincipalLogging.log.getAudienceFailure(e);
            }
        }
        return audSet;
    }

    @Override
    public Set<String> getGroups() {
        HashSet<String> groups = new HashSet<>();
        try {
            List<String> globalGroups = claimsSet.getStringListClaimValue(Claims.groups.name());
            if (globalGroups != null) {
                groups.addAll(globalGroups);
            }
        } catch (MalformedClaimException e) {
            PrincipalLogging.log.getGroupsFailure(e);
        }
        return groups;
    }

    @Override
    protected Collection<String> doGetClaimNames() {
        return claimsSet.getClaimNames();
    }

    @Override
    protected Object getClaimValue(String claimName) {
        Claims claimType = getClaimType(claimName);
        Object claim = null;

        // Handle the jose4j NumericDate types and
        switch (claimType) {
            case exp:
            case iat:
            case auth_time:
            case nbf:
            case updated_at:
                try {
                    Number numberClaim = claimsSet.getClaimValue(claimType.name(), Number.class);
                    if (numberClaim != null) {
                        claim = numberClaim.longValue();
                    }
                    if (claim == null) {
                        claim = 0L;
                    }
                } catch (MalformedClaimException e) {
                    PrincipalLogging.log.getGroupsFailure(claimName, e);
                }
                break;
            case groups:
                claim = getGroups();
                break;
            case aud:
                claim = getAudience();
                break;
            case UNKNOWN:
                claim = claimsSet.getClaimValue(claimName);
                break;
            default:
                claim = claimsSet.getClaimValue(claimType.name());
        }
        return claim;
    }

    /**
     * Convert the types jose4j uses for address, sub_jwk, and jwk
     */
    private void fixJoseTypes() {
        if (claimsSet.hasClaim(Claims.address.name())) {
            replaceClaimValueWithJsonValue(Claims.address.name());
        }
        if (claimsSet.hasClaim(Claims.jwk.name())) {
            replaceClaimValueWithJsonValue(Claims.jwk.name());
        }
        if (claimsSet.hasClaim(Claims.sub_jwk.name())) {
            replaceClaimValueWithJsonValue(Claims.sub_jwk.name());
        }
        // Handle custom claims
        Set<String> customClaimNames = filterCustomClaimNames(claimsSet.getClaimNames());
        for (String name : customClaimNames) {
            replaceClaimValueWithJsonValue(name);
        }
    }

    /**
     * Determine the custom claims in the set
     *
     * @param claimNames - the current set of claim names in this token
     * @return the possibly empty set of names for non-Claims claims
     */
    protected Set<String> filterCustomClaimNames(Collection<String> claimNames) {
        HashSet<String> customNames = new HashSet<>(claimNames);
        for (Claims claim : Claims.values()) {
            customNames.remove(claim.name());
        }
        return customNames;
    }

    protected void replaceClaimValueWithJsonValue(String name) {
        try {
            final Object object = claimsSet.getClaimValue(name, Object.class);
            if (!(object instanceof String)) {
                claimsSet.setClaim(name, JsonUtils.wrapValue(object));
            }
        } catch (MalformedClaimException e) {
            PrincipalLogging.log.replaceClaimValueWithJsonFailure(name, e);
        }
    }
}
