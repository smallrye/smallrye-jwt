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

import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * The public key and expected issuer needed to validate a token.
 */
public class JWTAuthContextInfo {
    private RSAPublicKey signerKey;
    private String issuedBy;
    private int expGracePeriodSecs = 60;
    private String publicKeyLocation;
    private Integer jwksRefreshInterval;
    private String tokenHeader = "Authorization";
    private String tokenCookie;
    private String tokenKeyId;
    private boolean requireNamedPrincipal = true;
    private String defaultSubClaim;
    private String subPath;
    private String defaultGroupsClaim;
    private String groupsPath;
    private List<String> whitelistAlgorithms = new ArrayList<>();
    /**
     * Flag that indicates whether the issuer is required and validated, or ignored, new in MP-JWT 1.1.
     */
    private boolean requireIssuer = true;

    public JWTAuthContextInfo() {
    }

    /**
     * Create an auth context from the token signer public key and issuer
     * 
     * @param signerKey
     * @param issuedBy
     */
    public JWTAuthContextInfo(RSAPublicKey signerKey, String issuedBy) {
        this.signerKey = signerKey;
        this.issuedBy = issuedBy;
    }

    public JWTAuthContextInfo(String publicKeyLocation, String issuedBy) {
        this.publicKeyLocation = publicKeyLocation;
        this.issuedBy = issuedBy;
    }

    /**
     * Create an auth context from an {@linkplain JWTAuthContextInfo} instance
     * 
     * @param orig
     */
    public JWTAuthContextInfo(JWTAuthContextInfo orig) {
        this.signerKey = orig.signerKey;
        this.issuedBy = orig.issuedBy;
        this.expGracePeriodSecs = orig.expGracePeriodSecs;
        this.publicKeyLocation = orig.publicKeyLocation;
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

    public String getPublicKeyLocation() {
        return this.publicKeyLocation;
    }

    public void setPublicKeyLocation(String publicKeyLocation) {
        this.publicKeyLocation = publicKeyLocation;
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

    public String getTokenHeader() {
        return tokenHeader;
    }

    public void setTokenHeader(String tokenHeader) {
        this.tokenHeader = tokenHeader;
    }

    public String getTokenCookie() {
        return tokenCookie;
    }

    public void setTokenCookie(String tokenCookie) {
        this.tokenCookie = tokenCookie;
    }

    public boolean isRequireNamedPrincipal() {
        return requireNamedPrincipal;
    }

    public void setRequireNamedPrincipal(final boolean requireNamedPrincipal) {
        this.requireNamedPrincipal = requireNamedPrincipal;
    }

    public String getDefaultSubjectClaim() {
        return defaultSubClaim;
    }

    public void setDefaultSubjectClaim(final String defaultSubClaim) {
        this.defaultSubClaim = defaultSubClaim;
    }

    public String getSubjectPath() {
        return subPath;
    }

    public void setSubjectPath(final String subPath) {
        this.subPath = subPath;
    }

    public String getDefaultGroupsClaim() {
        return defaultGroupsClaim;
    }

    public void setDefaultGroupsClaim(String defaultGroupsClaim) {
        this.defaultGroupsClaim = defaultGroupsClaim;
    }

    public String getGroupsPath() {
        return groupsPath;
    }

    public void setGroupsPath(String groupsPath) {
        this.groupsPath = groupsPath;
    }

    public List<String> getWhitelistAlgorithms() {
        return whitelistAlgorithms;
    }

    public void setWhitelistAlgorithms(final List<String> whitelistAlgorithms) {
        this.whitelistAlgorithms = whitelistAlgorithms;
    }

    public String getTokenKeyId() {
        return tokenKeyId;
    }

    public void setTokenKeyId(String tokenKeyId) {
        this.tokenKeyId = tokenKeyId;
    }
}
