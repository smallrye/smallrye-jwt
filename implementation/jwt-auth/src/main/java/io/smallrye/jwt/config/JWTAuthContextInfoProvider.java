/*
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
 *
 */
package io.smallrye.jwt.config;

import java.io.IOException;
import java.util.Optional;
import java.util.Set;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.config.Names;

import io.smallrye.jwt.KeyFormat;
import io.smallrye.jwt.SmallryeJwtUtils;
import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.util.KeyUtils;
import io.smallrye.jwt.util.ResourceUtils;

/**
 * A CDI provider for the JWTAuthContextInfo that obtains the necessary information from
 * MP config properties.
 */
@Dependent
public class JWTAuthContextInfoProvider {
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_SCHEME = "Bearer";
    private static final String NONE = "NONE";
    private static final String DEFAULT_GROUPS_SEPARATOR = " ";

    /**
     * Create JWTAuthContextInfoProvider with the public key and issuer
     *
     * @param publicKey the public key value
     * @param issuer the issuer
     * @return a new instance of JWTAuthContextInfoProvider
     */
    public static JWTAuthContextInfoProvider createWithKey(String publicKey, String issuer) {
        return create(publicKey, NONE, false, false, issuer);
    }

    /**
     * Create JWTAuthContextInfoProvider with the verification public key location and issuer
     *
     * @param keyLocation the verification public key location
     * @param issuer the issuer
     * @return a new instance of JWTAuthContextInfoProvider
     */
    public static JWTAuthContextInfoProvider createWithKeyLocation(String keyLocation, String issuer) {
        return create(NONE, keyLocation, false, false, issuer);
    }

    /**
     * Create JWTAuthContextInfoProvider with the verification public key location and issuer.
     * Tokens will be expected to contain either 'x5t' or 'x5t#S256' thumbprints.
     *
     * @param keyLocation certificate location which points to a PEM certificate or JWK containing the certificate chain
     * @param issuer the issuer
     * @return a new instance of JWTAuthContextInfoProvider
     */
    public static JWTAuthContextInfoProvider createWithCertificate(String keyLocation, String issuer) {
        return create(NONE, keyLocation, false, true, issuer);
    }

    /**
     * Create JWTAuthContextInfoProvider with the verification secret key location and issuer
     *
     * @param keyLocation the verification secret key location
     * @param issuer the issuer
     * @return a new instance of JWTAuthContextInfoProvider
     */
    public static JWTAuthContextInfoProvider createWithSecretKeyLocation(String keyLocation, String issuer) {
        return create(NONE, keyLocation, true, false, issuer);
    }

    private static JWTAuthContextInfoProvider create(String publicKey,
            String keyLocation,
            boolean secretKey,
            boolean verifyCertificateThumbprint,
            String issuer) {
        JWTAuthContextInfoProvider provider = new JWTAuthContextInfoProvider();
        provider.mpJwtPublicKey = Optional.of(publicKey);
        provider.mpJwtPublicKeyAlgorithm = Optional.of(SignatureAlgorithm.RS256);
        provider.mpJwtLocation = !secretKey ? Optional.of(keyLocation) : Optional.empty();
        provider.verifyKeyLocation = secretKey ? Optional.of(keyLocation) : Optional.empty();
        provider.verifyCertificateThumbprint = verifyCertificateThumbprint;
        provider.mpJwtIssuer = issuer;
        provider.mpJwtDecryptKeyLocation = Optional.empty();
        provider.decryptionKeyLocation = Optional.empty();
        provider.mpJwtRequireIss = Optional.of(Boolean.TRUE);
        provider.mpJwtTokenHeader = Optional.of(AUTHORIZATION_HEADER);
        provider.mpJwtTokenCookie = Optional.of(BEARER_SCHEME);
        provider.tokenHeader = provider.mpJwtTokenHeader;
        provider.tokenCookie = provider.mpJwtTokenCookie;
        provider.tokenKeyId = Optional.empty();
        provider.tokenDecryptionKeyId = Optional.empty();
        provider.tokenSchemes = Optional.of(BEARER_SCHEME);
        provider.requireNamedPrincipal = Optional.of(Boolean.TRUE);
        provider.defaultSubClaim = Optional.empty();
        provider.subPath = Optional.empty();
        provider.defaultGroupsClaim = Optional.empty();
        provider.groupsPath = Optional.empty();
        provider.expGracePeriodSecs = Optional.of(60);
        provider.maxTimeToLiveSecs = Optional.empty();
        provider.jwksRefreshInterval = Optional.empty();
        provider.forcedJwksRefreshInterval = 30;
        provider.signatureAlgorithm = Optional.of(SignatureAlgorithm.RS256);
        provider.keyEncryptionAlgorithm = KeyEncryptionAlgorithm.RSA_OAEP;
        provider.keyFormat = KeyFormat.ANY;
        provider.mpJwtVerifyAudiences = Optional.empty();
        provider.expectedAudience = Optional.empty();
        provider.groupsSeparator = DEFAULT_GROUPS_SEPARATOR;
        provider.requiredClaims = Optional.empty();

        return provider;
    }
    // The MP-JWT spec defined configuration properties

    /**
     * @since 1.1
     */
    @Inject
    @ConfigProperty(name = "mp.jwt.verify.publickey", defaultValue = NONE)
    private Optional<String> mpJwtPublicKey;
    /**
     * @since 1.2
     */
    @Inject
    @ConfigProperty(name = "mp.jwt.verify.publickey.algorithm")
    private Optional<SignatureAlgorithm> mpJwtPublicKeyAlgorithm;
    /**
     * @since 1.1
     */
    @Inject
    @ConfigProperty(name = "mp.jwt.verify.issuer", defaultValue = NONE)
    private String mpJwtIssuer;
    /**
     * @since 1.1
     */
    @Inject
    @ConfigProperty(name = "mp.jwt.verify.publickey.location", defaultValue = NONE)
    private Optional<String> mpJwtLocation;
    /**
     * @since 1.2
     */
    @Inject
    @ConfigProperty(name = "mp.jwt.decrypt.key.location", defaultValue = NONE)
    private Optional<String> mpJwtDecryptKeyLocation;

    /**
     * Verification key location.
     * This property can point to both public and secret keys and if it is set then 'mp.jwt.verify.publickey.location' will be
     * ignored.
     * Note that the secret keys will only recognized in the JWK format.
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.verify.key.location", defaultValue = NONE)
    private Optional<String> verifyKeyLocation;

    @Inject
    @ConfigProperty(name = "smallrye.jwt.decrypt.key.location")
    private Optional<String> decryptionKeyLocation;

    /**
     * Supported JSON Web Algorithm encryption algorithm.
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.decrypt.algorithm", defaultValue = "RSA_OAEP")
    private KeyEncryptionAlgorithm keyEncryptionAlgorithm;

    /**
     * Not part of the 1.1 release, but talked about.
     */
    @Deprecated
    @Inject
    @ConfigProperty(name = "mp.jwt.verify.requireiss", defaultValue = "true")
    private Optional<Boolean> mpJwtRequireIss;

    /**
     * @since 1.2
     */
    @Inject
    @ConfigProperty(name = Names.TOKEN_HEADER)
    private Optional<String> mpJwtTokenHeader;

    /**
     * @since 1.2
     */
    @Inject
    @ConfigProperty(name = Names.TOKEN_COOKIE)
    private Optional<String> mpJwtTokenCookie;

    /**
     * @since 1.2
     */
    @Inject
    @ConfigProperty(name = "mp.jwt.verify.audiences")
    Optional<Set<String>> mpJwtVerifyAudiences;

    // SmallRye JWT specific properties
    /**
     * HTTP header which is expected to contain a JWT token, default value is 'Authorization'
     *
     * @deprecated Use {@link JWTAuthContextInfoProvider#mpJwtTokenHeader}
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.token.header")
    @Deprecated
    private Optional<String> tokenHeader;

    /**
     * Cookie name containing a JWT token. This property is ignored unless the "smallrye.jwt.token.header" is set to 'Cookie'
     *
     * @deprecated Use {@link JWTAuthContextInfoProvider#mpJwtTokenCookie}
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.token.cookie")
    @Deprecated
    private Optional<String> tokenCookie;

    /**
     * If `true` then `Authorization` header will be checked even if the `smallrye.jwt.token.header` is set to `Cookie` but no
     * cookie with a `smallrye.jwt.token.cookie` name exists.
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.always-check-authorization", defaultValue = "false")
    private boolean alwaysCheckAuthorization;

    /**
     * Verification key identifier ('kid'). If it is set then if a signed JWT token contains 'kid' then both values must
     * match.
     * It will also be used to select a verification JWK key from a JWK set.
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.token.kid")
    private Optional<String> tokenKeyId;

    /**
     * Decryption key identifier ('kid'). If it is set then if an encrypted JWT token contains 'kid' then both values must
     * match.
     * It will also be used to select a decryption JWK key from a JWK set.
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.token.decryption.kid")
    private Optional<String> tokenDecryptionKeyId;

    /**
     * The scheme used with an HTTP Authorization header.
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.token.schemes", defaultValue = BEARER_SCHEME)
    private Optional<String> tokenSchemes;

    /**
     * Check that the JWT has at least one of 'sub', 'upn' or 'preferred_user_name' set. If not the JWT validation will
     * fail.
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.require.named-principal", defaultValue = "true")
    private Optional<Boolean> requireNamedPrincipal = Optional.of(Boolean.TRUE);

    /**
     * Default subject claim value. This property can be used to support the JWT tokens without a 'sub' claim.
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.claims.sub")
    private Optional<String> defaultSubClaim;

    /**
     * Path to the claim containing the sub. It starts from the top level JSON object and
     * can contain multiple segments where each segment represents a JSON object name only, example: "realm/sub".
     * Use double quotes with the namespace qualified claim names.
     * This property can be used if a token has no 'sub' claim but has the sub set in a different claim.
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.path.sub")
    private Optional<String> subPath;

    /**
     * Default groups claim value. This property can be used to support the JWT tokens without a 'groups' claim.
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.claims.groups")
    private Optional<String> defaultGroupsClaim;

    /**
     * Path to the claim containing an array of groups. It starts from the top level JSON object and
     * can contain multiple segments where each segment represents a JSON object name only, example: "realm/groups".
     * Use double quotes with the namespace qualified claim names.
     * This property can be used if a token has no 'groups' claim but has the groups set in a different claim.
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.path.groups")
    private Optional<String> groupsPath;

    /**
     * Separator for splitting a string which may contain multiple group values.
     * It will only be used if the "smallrye.jwt.path.groups" property points to a custom claim whose value is a string.
     * The default value is a single space because the standard 'scope' claim may contain a space separated sequence.
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.groups-separator", defaultValue = DEFAULT_GROUPS_SEPARATOR)
    private String groupsSeparator;

    @Inject
    @ConfigProperty(name = "smallrye.jwt.expiration.grace", defaultValue = "60")
    private Optional<Integer> expGracePeriodSecs;

    /**
     * The maximum number of seconds that a JWT may be issued for use. Effectively, the difference
     * between the expiration date of the JWT and the issued at date must not exceed this value.
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.time-to-live")
    Optional<Long> maxTimeToLiveSecs;

    /**
     * JWK cache refresh interval in minutes. It will be ignored unless the 'mp.jwt.verify.publickey.location' property points
     * to the HTTPS URL based JWK set.
     * Note this property will only be used if no HTTP Cache-Control response header with a positive 'max-age' parameter value
     * is available.
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.jwks.refresh-interval", defaultValue = "60")
    private Optional<Integer> jwksRefreshInterval;

    /**
     * Forced JWK cache refresh interval in minutes which is used to restrict the frequency of the forced refresh attempts which
     * may happen when the token verification fails due to the cache having no JWK key with a 'kid' property matching the
     * current token's 'kid' header.
     * It will be ignored unless the 'mp.jwt.verify.publickey.location' points to the HTTPS URL based JWK set.
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.jwks.forced-refresh-interval", defaultValue = "30")
    private int forcedJwksRefreshInterval;

    /**
     * Supported JSON Web Algorithm asymmetric signature algorithm (RS256 or ES256), default is RS256.
     *
     * @deprecated Use {@link JWTAuthContextInfoProvider#mpJwtPublicKeyAlgorithm}
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.verify.algorithm")
    @Deprecated
    private Optional<SignatureAlgorithm> signatureAlgorithm;

    /**
     * Verify the certificate thumbprint.
     * If this property is enabled then a signed token must contain either 'x5t' or 'x5t#256' X509Certificate thumbprint
     * headers.
     * Verification keys can only be in JWK or PEM Certificate key formats in this case.
     * JWK keys must have a 'x5c' (Base64-encoded X509Certificate) property set.
     * Note that 'smallrye.jwt.token.kid' property will have no effect as 'x5t' and 'x5t#S256'
     * are the key identifiers when this property is set.
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.verify.certificateThumbprint", defaultValue = "false")
    private boolean verifyCertificateThumbprint;

    /**
     * Supported key format. By default a key can be in any of the supported formats:
     * PEM key, PEM certificate, JWK key set or single JWK (possibly Base64URL-encoded).
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.verify.key-format", defaultValue = "ANY")
    private KeyFormat keyFormat;

    /**
     * Relax the validation of the verification keys.
     * Public RSA keys with the 1024 bit length will be allowed if this property is set to 'true'.
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.verify.relax-key-validation", defaultValue = "true")
    private boolean relaxVerificationKeyValidation = true;

    /**
     * The audience value(s) that identify valid recipient(s) of a JWT. Audience validation
     * will succeed, if any one of the provided values is equal to any one of the values of
     * the "aud" claim in the JWT. The config value should be specified as a comma-separated
     * list per MP Config requirements for a collection property.
     *
     * @since 2.0.3
     * @deprecated Use {@link JWTAuthContextInfoProvider#mpJwtVerifyAudiences}
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.verify.aud")
    @Deprecated
    Optional<Set<String>> expectedAudience;

    /**
     * List of claim names that must be present in the JWT for it to be valid. The configuration should be specified
     * as a comma-separated list.
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.required.claims")
    Optional<Set<String>> requiredClaims;

    @Produces
    Optional<JWTAuthContextInfo> getOptionalContextInfo() {
        Optional<String> resolvedVerifyKeyLocation = verifyKeyLocation.isPresent() && !NONE.equals(verifyKeyLocation.get())
                ? verifyKeyLocation
                : mpJwtLocation;

        // Log the config values
        ConfigLogging.log.configValues(mpJwtPublicKey.orElse("missing"), mpJwtIssuer,
                resolvedVerifyKeyLocation.orElse("missing"));
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();

        if (mpJwtIssuer != null && !mpJwtIssuer.equals(NONE)) {
            contextInfo.setIssuedBy(mpJwtIssuer.trim());
        }

        if (mpJwtPublicKey.isPresent() && !NONE.equals(mpJwtPublicKey.get())) {
            contextInfo.setPublicKeyContent(mpJwtPublicKey.get());
        } else if (resolvedVerifyKeyLocation.isPresent() && !NONE.equals(resolvedVerifyKeyLocation.get())) {
            String resolvedVerifyKeyLocationTrimmed = resolvedVerifyKeyLocation.get().trim();
            if (resolvedVerifyKeyLocationTrimmed.startsWith("http")) {
                contextInfo.setPublicKeyLocation(resolvedVerifyKeyLocationTrimmed);
            } else {
                try {
                    contextInfo.setPublicKeyContent(ResourceUtils.readResource(resolvedVerifyKeyLocationTrimmed));
                    if (contextInfo.getPublicKeyContent() == null) {
                        throw ConfigMessages.msg.invalidPublicKeyLocation();
                    }
                } catch (IOException ex) {
                    throw ConfigMessages.msg.readingPublicKeyLocationFailed(ex);
                }
            }
        }

        final Optional<String> theDecryptionKeyLocation;
        if (mpJwtDecryptKeyLocation.isPresent()) {
            theDecryptionKeyLocation = mpJwtDecryptKeyLocation;
        } else if (decryptionKeyLocation.isPresent()) {
            //ConfigLogging.log.replacedConfig("smallrye.jwt.decrypt.key.location", "mp.jwt.decrypt.key.location");
            theDecryptionKeyLocation = decryptionKeyLocation;
        } else {
            theDecryptionKeyLocation = Optional.empty();
        }

        if (theDecryptionKeyLocation.isPresent() && !NONE.equals(theDecryptionKeyLocation.get())) {
            String decryptionKeyLocationTrimmed = theDecryptionKeyLocation.get().trim();
            if (decryptionKeyLocationTrimmed.startsWith("http")) {
                contextInfo.setDecryptionKeyLocation(decryptionKeyLocationTrimmed);
            } else {
                try {
                    contextInfo.setDecryptionKeyContent(ResourceUtils.readResource(decryptionKeyLocationTrimmed));
                    if (contextInfo.getDecryptionKeyContent() == null) {
                        throw ConfigMessages.msg.invalidDecryptKeyLocation();
                    }
                } catch (IOException ex) {
                    throw ConfigMessages.msg.readingDecryptKeyLocationFailed(ex);
                }
            }
        }

        if (mpJwtTokenHeader.isPresent()) {
            contextInfo.setTokenHeader(mpJwtTokenHeader.get());
        } else if (tokenHeader.isPresent()) {
            ConfigLogging.log.replacedConfig("smallrye.jwt.token.header", "mp.jwt.token.header");
            contextInfo.setTokenHeader(tokenHeader.get());
        } else {
            contextInfo.setTokenHeader(AUTHORIZATION_HEADER);
        }

        if (mpJwtTokenCookie.isPresent()) {
            SmallryeJwtUtils.setContextTokenCookie(contextInfo, mpJwtTokenCookie);
        } else if (tokenCookie.isPresent()) {
            ConfigLogging.log.replacedConfig("smallrye.jwt.token.cookie", "mp.jwt.token.cookie");
            SmallryeJwtUtils.setContextTokenCookie(contextInfo, tokenCookie);
        } else {
            SmallryeJwtUtils.setContextTokenCookie(contextInfo, Optional.of(BEARER_SCHEME));
        }

        contextInfo.setAlwaysCheckAuthorization(alwaysCheckAuthorization);
        contextInfo.setTokenKeyId(tokenKeyId.orElse(null));
        contextInfo.setTokenDecryptionKeyId(tokenDecryptionKeyId.orElse(null));
        contextInfo.setRequireNamedPrincipal(requireNamedPrincipal.orElse(null));
        SmallryeJwtUtils.setTokenSchemes(contextInfo, tokenSchemes);
        contextInfo.setDefaultSubjectClaim(defaultSubClaim.orElse(null));
        SmallryeJwtUtils.setContextSubPath(contextInfo, subPath);
        contextInfo.setDefaultGroupsClaim(defaultGroupsClaim.orElse(null));
        SmallryeJwtUtils.setContextGroupsPath(contextInfo, groupsPath);
        contextInfo.setExpGracePeriodSecs(expGracePeriodSecs.orElse(null));
        contextInfo.setMaxTimeToLiveSecs(maxTimeToLiveSecs.orElse(null));
        contextInfo.setJwksRefreshInterval(jwksRefreshInterval.orElse(null));
        contextInfo.setForcedJwksRefreshInterval(forcedJwksRefreshInterval);
        final Optional<SignatureAlgorithm> resolvedAlgorithm;
        if (mpJwtPublicKeyAlgorithm.isPresent()) {
            resolvedAlgorithm = mpJwtPublicKeyAlgorithm;
        } else if (signatureAlgorithm.isPresent()) {
            ConfigLogging.log.replacedConfig("smallrye.jwt.verify.algorithm", "mp.jwt.verify.publickey.algorithm");
            resolvedAlgorithm = signatureAlgorithm;
        } else {
            resolvedAlgorithm = Optional.empty();
        }
        if (resolvedAlgorithm.isPresent()) {
            if (resolvedAlgorithm.get() == SignatureAlgorithm.HS256 && resolvedVerifyKeyLocation == mpJwtLocation) {
                throw ConfigMessages.msg.hs256NotSupported();
            }
            contextInfo.setSignatureAlgorithm(resolvedAlgorithm.get());
        } else {
            contextInfo.setSignatureAlgorithm(SignatureAlgorithm.RS256);
        }

        contextInfo.setKeyEncryptionAlgorithm(keyEncryptionAlgorithm);
        contextInfo.setKeyFormat(keyFormat);
        if (mpJwtVerifyAudiences.isPresent()) {
            contextInfo.setExpectedAudience(mpJwtVerifyAudiences.get());
        } else if (expectedAudience.isPresent()) {
            ConfigLogging.log.replacedConfig("smallrye.jwt.verify.aud", "mp.jwt.verify.audiences");
            contextInfo.setExpectedAudience(expectedAudience.get());
        } else {
            contextInfo.setExpectedAudience(null);
        }
        contextInfo.setGroupsSeparator(groupsSeparator);
        contextInfo.setRequiredClaims(requiredClaims.orElse(null));
        contextInfo.setRelaxVerificationKeyValidation(relaxVerificationKeyValidation);
        contextInfo.setVerifyCertificateThumbprint(verifyCertificateThumbprint);
        return Optional.of(contextInfo);
    }

    public Optional<String> getMpJwtPublicKey() {
        return mpJwtPublicKey;
    }

    public Optional<SignatureAlgorithm> getMpJwtPublicKeyAlgorithm() {
        return mpJwtPublicKeyAlgorithm;
    }

    public Optional<String> getMpJwtDecryptKeyLocation() {
        return mpJwtDecryptKeyLocation;
    }

    public String getMpJwtIssuer() {
        return mpJwtIssuer;
    }

    public Optional<String> getMpJwtLocation() {
        return mpJwtLocation;
    }

    public Optional<Boolean> getMpJwtRequireIss() {
        return mpJwtRequireIss;
    }

    public Optional<String> getMpJwtTokenHeader() {
        return mpJwtTokenHeader;
    }

    public Optional<String> getMpJwtTokenCookie() {
        return mpJwtTokenCookie;
    }

    public Optional<Set<String>> getMpJwtVerifyAudiences() {
        return mpJwtVerifyAudiences;
    }

    @Deprecated
    public Optional<String> getTokenHeader() {
        return tokenHeader;
    }

    @Deprecated
    public Optional<String> getTokenCookie() {
        return tokenCookie;
    }

    public boolean isAlwaysCheckAuthorization() {
        return alwaysCheckAuthorization;
    }

    public Optional<String> getTokenKeyId() {
        return tokenKeyId;
    }

    public Optional<String> getTokenSchemes() {
        return tokenSchemes;
    }

    public Optional<Integer> getExpGracePeriodSecs() {
        return expGracePeriodSecs;
    }

    public Optional<Long> getMaxTimeToLiveSecs() {
        return maxTimeToLiveSecs;
    }

    public Optional<Integer> getJwksRefreshInterval() {
        return jwksRefreshInterval;
    }

    public int getForcedJwksRefreshInterval() {
        return forcedJwksRefreshInterval;
    }

    public Optional<String> getDefaultGroupsClaim() {
        return defaultGroupsClaim;
    }

    public Optional<String> getGroupsPath() {
        return groupsPath;
    }

    public String getGroupsSeparator() {
        return groupsSeparator;
    }

    public Optional<String> getSubjectPath() {
        return subPath;
    }

    public Optional<String> getDefaultSubjectClaim() {
        return defaultSubClaim;
    }

    public KeyFormat getKeyFormat() {
        return keyFormat;
    }

    public Optional<Set<String>> getRequiredClaims() {
        return requiredClaims;
    }

    public boolean isRelaxVerificationKeyValidation() {
        return relaxVerificationKeyValidation;
    }

    @Produces
    @ApplicationScoped
    public JWTAuthContextInfo getContextInfo() {
        return getOptionalContextInfo().get();
    }
}
