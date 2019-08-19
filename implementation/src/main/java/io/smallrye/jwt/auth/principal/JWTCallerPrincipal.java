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

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.json.JsonValue;
import javax.security.auth.Subject;

import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;

import io.smallrye.jwt.JsonUtils;

/**
 * An abstract CallerPrincipal implementation that provides access to the JWT claims that are required by
 * the microprofile token.
 */
public abstract class JWTCallerPrincipal implements JsonWebToken {

    private final String rawToken;
    private final String tokenType;

    /**
     * Create a JWTCallerPrincipal with the caller's name
     *
     * @param rawToken - raw token value
     * @param tokenType - token type
     */
    public JWTCallerPrincipal(String rawToken, String tokenType) {
        this.rawToken = rawToken;
        this.tokenType = tokenType;
    }

    @Override
    public String getName() {
        String principalName = getClaim(Claims.upn.name());
        if (principalName == null) {
            principalName = getClaim(Claims.preferred_username.name());
            if (principalName == null) {
                principalName = getClaim(Claims.sub.name());
            }
        }
        return principalName;
    }

    @Override
    public Set<String> getClaimNames() {
        Set<String> names = new HashSet<>(doGetClaimNames());
        names.add(Claims.raw_token.name());
        return names;
    }

    protected abstract Collection<String> doGetClaimNames();

    @Override
    public <T> T getClaim(String claimName) {
        @SuppressWarnings("unchecked")
        T claimValue = Claims.raw_token.name().equals(claimName) ? (T) rawToken : (T) getClaimValue(claimName);
        return claimValue;
    }

    protected abstract Object getClaimValue(String claimName);

    @Override
    public boolean implies(Subject subject) {
        return false;
    }

    public String toString() {
        return toString(false);
    }

    /**
     * TODO: showAll is ignored and currently assumed true
     *
     * @param showAll - should all claims associated with the JWT be displayed or should only those defined in the
     *        JsonWebToken interface be displayed.
     * @return JWTCallerPrincipal string view
     */
    public String toString(boolean showAll) {
        String toString = "DefaultJWTCallerPrincipal{" +
                "id='" + getTokenID() + '\'' +
                ", name='" + getName() + '\'' +
                ", expiration=" + getExpirationTime() +
                ", notBefore=" + getClaim(Claims.nbf.name()) +
                ", issuedAt=" + getIssuedAtTime() +
                ", issuer='" + getIssuer() + '\'' +
                ", audience=" + getAudience() +
                ", subject='" + getSubject() + '\'' +
                ", type='" + tokenType + '\'' +
                ", issuedFor='" + getClaim("azp") + '\'' +
                ", authTime=" + getClaim("auth_time") +
                ", givenName='" + getClaim("given_name") + '\'' +
                ", familyName='" + getClaim("family_name") + '\'' +
                ", middleName='" + getClaim("middle_name") + '\'' +
                ", nickName='" + getClaim("nickname") + '\'' +
                ", preferredUsername='" + getClaim("preferred_username") + '\'' +
                ", email='" + getClaim("email") + '\'' +
                ", emailVerified=" + getClaim(Claims.email_verified.name()) +
                ", allowedOrigins=" + getClaim("allowedOrigins") +
                ", updatedAt=" + getClaim("updated_at") +
                ", acr='" + getClaim("acr") + '\'';
        StringBuilder tmp = new StringBuilder(toString);
        tmp.append(", groups=[");
        for (String group : getGroups()) {
            tmp.append(group);
            tmp.append(',');
        }
        tmp.setLength(tmp.length() - 1);
        tmp.append("]}");
        return tmp.toString();
    }

    protected JsonValue wrapClaimValue(Object value) {
        return JsonUtils.wrapValue(value);
    }

    protected Claims getClaimType(String claimName) {
        Claims claimType;
        try {
            claimType = Claims.valueOf(claimName);
        } catch (IllegalArgumentException e) {
            claimType = Claims.UNKNOWN;
        }
        return claimType;
    }
}
