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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import javax.crypto.SecretKey;

import io.smallrye.jwt.KeyFormat;
import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;

/**
 * The public key and expected issuer needed to validate a token.
 */
public class JWTAuthContextInfo {
    private PublicKey publicVerificationKey;
    private SecretKey secretVerificationKey;
    private PrivateKey privateDecryptionKey;
    private SecretKey secretDecryptionKey;
    private String issuedBy;
    private int expGracePeriodSecs = 60;
    private Long maxTimeToLiveSecs;
    private String publicKeyLocation;
    private String publicKeyContent;
    private String decryptionKeyLocation;
    private String decryptionKeyContent;
    private Integer jwksRefreshInterval;
    private int forcedJwksRefreshInterval = 30;
    private String tokenHeader = "Authorization";
    private String tokenCookie;
    private boolean alwaysCheckAuthorization;
    private String tokenKeyId;
    private String tokenDecryptionKeyId;
    private List<String> tokenSchemes = Collections.singletonList("Bearer");
    private boolean requireNamedPrincipal = true;
    private String defaultSubClaim;
    private String subPath;
    private String defaultGroupsClaim;
    private String groupsPath;
    private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RS256;
    private KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.RSA_OAEP;
    private KeyFormat keyFormat = KeyFormat.ANY;
    private Set<String> expectedAudience;
    private String groupsSeparator = " ";
    private Set<String> requiredClaims;
    private boolean relaxVerificationKeyValidation = true;
    private boolean verifyCertificateThumbprint;

    public JWTAuthContextInfo() {
    }

    public JWTAuthContextInfo(PublicKey verificationKey, String issuedBy) {
        this.publicVerificationKey = verificationKey;
        this.issuedBy = issuedBy;
    }

    public JWTAuthContextInfo(SecretKey verificationKey, String issuedBy) {
        this.secretVerificationKey = verificationKey;
        this.issuedBy = issuedBy;
    }

    public JWTAuthContextInfo(String publicKeyLocation, String issuedBy) {
        this.publicKeyLocation = publicKeyLocation;
        this.issuedBy = issuedBy;
    }

    /**
     * Create an auth context from an {@linkplain JWTAuthContextInfo} instance
     *
     * @param orig the original instance to copy
     */
    public JWTAuthContextInfo(JWTAuthContextInfo orig) {
        this.publicVerificationKey = orig.publicVerificationKey;
        this.secretVerificationKey = orig.secretVerificationKey;
        this.privateDecryptionKey = orig.privateDecryptionKey;
        this.secretDecryptionKey = orig.secretDecryptionKey;
        this.issuedBy = orig.issuedBy;
        this.expGracePeriodSecs = orig.expGracePeriodSecs;
        this.maxTimeToLiveSecs = orig.maxTimeToLiveSecs;
        this.publicKeyLocation = orig.publicKeyLocation;
        this.publicKeyContent = orig.publicKeyContent;
        this.decryptionKeyLocation = orig.decryptionKeyLocation;
        this.decryptionKeyContent = orig.decryptionKeyContent;
        this.jwksRefreshInterval = orig.jwksRefreshInterval;
        this.forcedJwksRefreshInterval = orig.forcedJwksRefreshInterval;
        this.tokenHeader = orig.tokenHeader;
        this.tokenCookie = orig.tokenCookie;
        this.alwaysCheckAuthorization = orig.alwaysCheckAuthorization;
        this.tokenKeyId = orig.tokenKeyId;
        this.tokenDecryptionKeyId = orig.tokenDecryptionKeyId;
        this.tokenSchemes = orig.tokenSchemes;
        this.requireNamedPrincipal = orig.requireNamedPrincipal;
        this.defaultSubClaim = orig.defaultSubClaim;
        this.subPath = orig.subPath;
        this.defaultGroupsClaim = orig.defaultGroupsClaim;
        this.groupsPath = orig.groupsPath;
        this.signatureAlgorithm = orig.signatureAlgorithm;
        this.keyEncryptionAlgorithm = orig.keyEncryptionAlgorithm;
        this.keyFormat = orig.keyFormat;
        this.expectedAudience = orig.expectedAudience;
        this.groupsSeparator = orig.groupsSeparator;
        this.requiredClaims = orig.requiredClaims;
        this.relaxVerificationKeyValidation = orig.relaxVerificationKeyValidation;
        this.verifyCertificateThumbprint = orig.verifyCertificateThumbprint;
    }

    @Deprecated
    public RSAPublicKey getSignerKey() {
        return (RSAPublicKey) publicVerificationKey;
    }

    @Deprecated
    public void setSignerKey(RSAPublicKey signerKey) {
        this.publicVerificationKey = signerKey;
    }

    public PublicKey getPublicVerificationKey() {
        return publicVerificationKey;
    }

    public void setPublicVerificationKey(PublicKey verificationKey) {
        this.publicVerificationKey = verificationKey;
    }

    public SecretKey getSecretVerificationKey() {
        return secretVerificationKey;
    }

    public void setSecretVerificationKey(SecretKey verificationKey) {
        this.secretVerificationKey = verificationKey;
    }

    public PrivateKey getPrivateDecryptionKey() {
        return privateDecryptionKey;
    }

    public void setPrivateDecryptionKey(PrivateKey decryptionKey) {
        this.privateDecryptionKey = decryptionKey;
    }

    public SecretKey getSecretDecryptionKey() {
        return secretDecryptionKey;
    }

    public void setSecretDecryptionKey(SecretKey decryptionKey) {
        this.secretDecryptionKey = decryptionKey;
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

    public Long getMaxTimeToLiveSecs() {
        return maxTimeToLiveSecs;
    }

    public void setMaxTimeToLiveSecs(Long maxTimeToLiveSecs) {
        this.maxTimeToLiveSecs = maxTimeToLiveSecs;
    }

    public String getPublicKeyLocation() {
        return this.publicKeyLocation;
    }

    public void setPublicKeyLocation(String publicKeyLocation) {
        this.publicKeyLocation = publicKeyLocation;
    }

    public String getDecryptionKeyLocation() {
        return this.decryptionKeyLocation;
    }

    public void setDecryptionKeyLocation(String keyLocation) {
        this.decryptionKeyLocation = keyLocation;
    }

    public KeyEncryptionAlgorithm getKeyEncryptionAlgorithm() {
        return this.keyEncryptionAlgorithm;
    }

    public void setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm algorithm) {
        this.keyEncryptionAlgorithm = algorithm;
    }

    public String getPublicKeyContent() {
        return this.publicKeyContent;
    }

    public void setPublicKeyContent(String publicKeyContent) {
        this.publicKeyContent = publicKeyContent;
    }

    public String getDecryptionKeyContent() {
        return this.decryptionKeyContent;
    }

    public void setDecryptionKeyContent(String keyContent) {
        this.decryptionKeyContent = keyContent;
    }

    public Integer getJwksRefreshInterval() {
        return jwksRefreshInterval;
    }

    public void setJwksRefreshInterval(Integer jwksRefreshInterval) {
        this.jwksRefreshInterval = jwksRefreshInterval;
    }

    public int getForcedJwksRefreshInterval() {
        return forcedJwksRefreshInterval;
    }

    public void setForcedJwksRefreshInterval(int forcedJwksRefreshInterval) {
        this.forcedJwksRefreshInterval = forcedJwksRefreshInterval;
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

    public String getTokenKeyId() {
        return tokenKeyId;
    }

    public void setTokenKeyId(String tokenKeyId) {
        this.tokenKeyId = tokenKeyId;
    }

    public String getTokenDecryptionKeyId() {
        return tokenDecryptionKeyId;
    }

    public void setTokenDecryptionKeyId(String tokenKeyId) {
        this.tokenDecryptionKeyId = tokenKeyId;
    }

    public List<String> getTokenSchemes() {
        return tokenSchemes;
    }

    public void setTokenSchemes(final List<String> tokenSchemes) {
        this.tokenSchemes = tokenSchemes;
    }

    public Set<String> getExpectedAudience() {
        return expectedAudience;
    }

    public void setExpectedAudience(Set<String> expectedAudience) {
        this.expectedAudience = expectedAudience;
    }

    public String getGroupsSeparator() {
        return groupsSeparator;
    }

    public void setGroupsSeparator(String groupsSeparator) {
        this.groupsSeparator = groupsSeparator;
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public KeyFormat getKeyFormat() {
        return keyFormat;
    }

    public void setKeyFormat(KeyFormat keyFormat) {
        this.keyFormat = keyFormat;
    }

    public boolean isAlwaysCheckAuthorization() {
        return alwaysCheckAuthorization;
    }

    public void setAlwaysCheckAuthorization(boolean alwaysCheckAuthorization) {
        this.alwaysCheckAuthorization = alwaysCheckAuthorization;
    }

    public Set<String> getRequiredClaims() {
        return requiredClaims;
    }

    public void setRequiredClaims(final Set<String> requiredClaims) {
        this.requiredClaims = requiredClaims;
    }

    @Override
    public String toString() {
        return "JWTAuthContextInfo{" +
                "publicVerificationKey=" + publicVerificationKey +
                ", secretVerificationKey=" + secretVerificationKey +
                ", privateDecryptionKey=" + privateDecryptionKey +
                ", secretDecryptionKey=" + secretDecryptionKey +
                ", issuedBy='" + issuedBy + '\'' +
                ", expGracePeriodSecs=" + expGracePeriodSecs +
                ", maxTimeToLiveSecs=" + maxTimeToLiveSecs +
                ", publicKeyLocation='" + publicKeyLocation + '\'' +
                ", publicKeyContent='" + publicKeyContent + '\'' +
                ", decryptionKeyLocation='" + decryptionKeyLocation + '\'' +
                ", decryptionKeyContent='" + decryptionKeyContent + '\'' +
                ", jwksRefreshInterval=" + jwksRefreshInterval +
                ", tokenHeader='" + tokenHeader + '\'' +
                ", tokenCookie='" + tokenCookie + '\'' +
                ", alwaysCheckAuthorization=" + alwaysCheckAuthorization +
                ", tokenKeyId='" + tokenKeyId + '\'' +
                ", tokenDecryptionKeyId='" + tokenDecryptionKeyId + '\'' +
                ", tokenSchemes=" + tokenSchemes +
                ", requireNamedPrincipal=" + requireNamedPrincipal +
                ", defaultSubClaim='" + defaultSubClaim + '\'' +
                ", subPath='" + subPath + '\'' +
                ", defaultGroupsClaim='" + defaultGroupsClaim + '\'' +
                ", groupsPath='" + groupsPath + '\'' +
                ", signatureAlgorithm=" + signatureAlgorithm +
                ", keyEncryptionAlgorithm=" + keyEncryptionAlgorithm +
                ", keyFormat=" + keyFormat +
                ", expectedAudience=" + expectedAudience +
                ", groupsSeparator='" + groupsSeparator + '\'' +
                ", relaxVerificationKeyValidation=" + relaxVerificationKeyValidation +
                ", verifyCertificateThumbprint=" + verifyCertificateThumbprint +
                '}';
    }

    public boolean isRelaxVerificationKeyValidation() {
        return relaxVerificationKeyValidation;
    }

    public void setRelaxVerificationKeyValidation(boolean relaxVerificationKeyValidation) {
        this.relaxVerificationKeyValidation = relaxVerificationKeyValidation;
    }

    public boolean isVerifyCertificateThumbprint() {
        return verifyCertificateThumbprint;
    }

    public void setVerifyCertificateThumbprint(boolean verifyCertificateThumbprint) {
        this.verifyCertificateThumbprint = verifyCertificateThumbprint;
    }
}
