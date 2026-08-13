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
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.eclipse.microprofile.jwt.Claims;

import com.nimbusds.jwt.JWTClaimsSet;

import io.smallrye.jwt.JsonUtils;
import io.smallrye.jwt.common.JwtClaims;

/**
 * A default implementation of JWTCallerPrincipal that wraps a claims map.
 */
public class DefaultJWTCallerPrincipal extends JWTCallerPrincipal {
    private final JwtClaims claimsSet;

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

    public DefaultJWTCallerPrincipal(JWTClaimsSet nimbusClaimsSet) {
        this(new JwtClaims(nimbusClaimsSet.getClaims()));
    }

    protected static String getRawToken(JwtClaims claimsSet) {
        Object rawToken = claimsSet.getClaim(Claims.raw_token.name());
        return rawToken != null ? rawToken.toString() : null;
    }

    @Override
    public Set<String> getAudience() {
        List<String> audList = claimsSet.getAudience();
        return audList != null ? new LinkedHashSet<>(audList) : null;
    }

    @Override
    public Set<String> getGroups() {
        List<String> groupsList = claimsSet.getGroups();
        return groupsList != null ? new HashSet<>(groupsList) : new HashSet<>();
    }

    @Override
    protected Collection<String> doGetClaimNames() {
        return claimsSet.getClaimNames();
    }

    @Override
    protected Object getClaimValue(String claimName) {
        Claims claimType = getClaimType(claimName);
        Object claim = null;

        switch (claimType) {
            case exp:
            case iat:
            case auth_time:
            case nbf:
            case updated_at:
                Object value = claimsSet.getClaim(claimType.name());
                if (value instanceof Number) {
                    claim = ((Number) value).longValue();
                } else if (value instanceof Date) {
                    claim = ((Date) value).getTime() / 1000;
                } else if (value != null) {
                    PrincipalLogging.log.claimTypeMismatch(claimName, claimType.getType().getSimpleName(),
                            value.getClass().getSimpleName());
                }
                if (claim == null) {
                    claim = 0L;
                }
                break;
            case groups:
                claim = getGroups();
                break;
            case aud:
                claim = getAudience();
                break;
            case UNKNOWN:
                claim = claimsSet.getClaim(claimName);
                break;
            default:
                claim = claimsSet.getClaim(claimType.name());
        }
        return claim;
    }

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
        // Handle custom claimsSet
        Set<String> customClaimNames = filterCustomClaimNames(claimsSet.keySet());
        for (String name : customClaimNames) {
            replaceClaimValueWithJsonValue(name);
        }
    }

    protected Set<String> filterCustomClaimNames(Collection<String> claimNames) {
        HashSet<String> customNames = new HashSet<>(claimNames);
        for (Claims claim : Claims.values()) {
            customNames.remove(claim.name());
        }
        return customNames;
    }

    protected void replaceClaimValueWithJsonValue(String name) {
        final Object object = claimsSet.getClaim(name);
        if (object != null && !(object instanceof String)) {
            claimsSet.setClaim(name, JsonUtils.wrapValue(object));
        }
    }
}
