/**
 *
 *   Copyright 2018 Red Hat, Inc, and individual contributors.
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


import java.security.interfaces.RSAPublicKey;

/**
 * The public key and expected issuer needed to validate a token.
 */
public class JWTAuthContextInfo {
    private RSAPublicKey signerKey;
    private String issuedBy;
    private int expGracePeriodSecs = 60;
    private String jwksUri;
    private Integer jwksRefreshInterval;
    private String tokenHeader = "Authorization";
    private String tokenCookie;
    private String defaultGroups;
    /**
     * Flag that indicates whether the issuer is required and validated, or ignored, new in MP-JWT 1.1.
     */
    private boolean requireIssuer = true;
    private boolean followMpJwt11Rules;

    public JWTAuthContextInfo() {
    }

    /**
     * Create an auth context from the token signer public key and issuer
     * @param signerKey
     * @param issuedBy
     */
    public JWTAuthContextInfo(RSAPublicKey signerKey, String issuedBy) {
        this.signerKey = signerKey;
        this.issuedBy = issuedBy;
    }

    /**
     * Create an auth context from an {@linkplain JWTAuthContextInfo} instance
     * @param orig
     */
    public JWTAuthContextInfo(JWTAuthContextInfo orig) {
        this.signerKey = orig.signerKey;
        this.issuedBy = orig.issuedBy;
        this.expGracePeriodSecs = orig.expGracePeriodSecs;
        this.jwksUri = orig.jwksUri;
        this.jwksRefreshInterval = orig.jwksRefreshInterval;
    }

    public RSAPublicKey getSignerKey() {
        return signerKey;
    }

    public void setSignerKey(RSAPublicKey signerKey) {
        this.signerKey = signerKey;
    }

    public String getIssuedBy() {
        return issuedBy;
    }

    public void setIssuedBy(String issuedBy) {
        this.issuedBy = issuedBy;
    }

    public int getExpGracePeriodSecs() {
        return expGracePeriodSecs;
    }

    public void setExpGracePeriodSecs(int expGracePeriodSecs) {
        this.expGracePeriodSecs = expGracePeriodSecs;
    }

    public String getJwksUri() {
        return jwksUri;
    }

    public void setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
    }

    public Integer getJwksRefreshInterval() {
        return jwksRefreshInterval;
    }

    public void setJwksRefreshInterval(Integer jwksRefreshInterval) {
        this.jwksRefreshInterval = jwksRefreshInterval;
    }

    public boolean isRequireIssuer() {
        return requireIssuer;
    }

    public void setRequireIssuer(boolean requireIssuer) {
        this.requireIssuer = requireIssuer;
    }

    /**
     * Is the {@linkplain #jwksUri} a location that follows the MP-JWT 1.1 rules for the mp.jwt.verify.publickey.location
     * property? These rules allow for any URL type to one of PEM, JWK or JWKS contents.
     * @return true if jwksUri was set from the mp.jwt.verify.publickey.location, false otherwise
     */
    public boolean isFollowMpJwt11Rules() {
        return followMpJwt11Rules;
    }

    public void setFollowMpJwt11Rules(boolean followMpJwt11Rules) {
        this.followMpJwt11Rules = followMpJwt11Rules;
    }

    public String getTokenHeader() {
        return tokenHeader;
    }

    public void setTokenHeader(String tokenHeader) {
        this.tokenHeader = tokenHeader;
    }

    public String getDefaultGroups() {
        return defaultGroups;
    }

    public void setDefaultGroups(String defaultGroups) {
        this.defaultGroups = defaultGroups;
    }

    public String getTokenCookie() {
        return tokenCookie;
    }

    public void setTokenCookie(String tokenCookie) {
        this.tokenCookie = tokenCookie;
    }
}
