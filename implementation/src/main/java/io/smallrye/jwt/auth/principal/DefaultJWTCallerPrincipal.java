/**
 *
 *   Copyright 2017 Red Hat, Inc, and individual contributors.
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
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.json.JsonArray;
import javax.json.JsonNumber;
import javax.json.JsonObject;

import org.eclipse.microprofile.jwt.Claims;
import org.jboss.logging.Logger;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;

/**
 * A default implementation of JWTCallerPrincipal that wraps the jose4j JwtClaims.
 *
 * @see JwtClaims
 */
public class DefaultJWTCallerPrincipal extends JWTCallerPrincipal {
    private static Logger logger = Logger.getLogger(DefaultJWTCallerPrincipal.class);

    private JwtClaims claimsSet;

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
        try {
            if (claimsSet.hasClaim(Claims.aud.name())) {
                List<String> audList = claimsSet.getStringListClaimValue(Claims.aud.name());
                audSet = new HashSet<>(audList);
            }
        } catch (MalformedClaimException e) {
            try {
                // Not sent as an array, try a single value
                String aud = claimsSet.getStringClaimValue(Claims.aud.name());
                audSet = new HashSet<>();
                audSet.add(aud);
            } catch (MalformedClaimException e1) {
                logger.warn("getAudience failure: ", e);
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
            logger.warn("getGroups failure: ", e);
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
                    claim = claimsSet.getClaimValue(claimType.name(), Long.class);
                    if (claim == null) {
                        claim = new Long(0);
                    }
                } catch (MalformedClaimException e) {
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
            replaceMap(Claims.address.name());
        }
        if (claimsSet.hasClaim(Claims.jwk.name())) {
            replaceMap(Claims.jwk.name());
        }
        if (claimsSet.hasClaim(Claims.sub_jwk.name())) {
            replaceMap(Claims.sub_jwk.name());
        }
        // Handle custom claims
        Set<String> customClaimNames = filterCustomClaimNames(claimsSet.getClaimNames());
        for (String name : customClaimNames) {
            Object claimValue = claimsSet.getClaimValue(name);
            if (claimValue instanceof List) {
                replaceList(name);
            } else if (claimValue instanceof Map) {
                replaceMap(name);
            } else if (claimValue instanceof Number) {
                replaceNumber(name);
            }
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

    /**
     * Replace the jose4j Map with a JsonObject
     *
     * @param name - claim name
     */
    protected void replaceMap(String name) {
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> map = claimsSet.getClaimValue(name, Map.class);
            JsonObject jsonObject = replaceMapClaims(map);
            claimsSet.setClaim(name, jsonObject);
        } catch (MalformedClaimException e) {
            logger.warn("replaceMap failure for: " + name, e);
        }
    }

    /**
     * Replace the jose4j List with a JsonArray
     *
     * @param name - claim name
     */
    protected void replaceList(String name) {
        try {
            JsonArray array = (JsonArray) wrapClaimValue(claimsSet.getClaimValue(name, List.class));
            claimsSet.setClaim(name, array);
        } catch (MalformedClaimException e) {
            logger.warn("replaceList failure for: " + name, e);
        }
    }

    protected void replaceNumber(String name) {
        try {
            Number number = claimsSet.getClaimValue(name, Number.class);
            JsonNumber jsonNumber = (JsonNumber) wrapClaimValue(number);
            claimsSet.setClaim(name, jsonNumber);
        } catch (MalformedClaimException e) {
            logger.warn("replaceNumber failure for: " + name, e);
        }
    }
}