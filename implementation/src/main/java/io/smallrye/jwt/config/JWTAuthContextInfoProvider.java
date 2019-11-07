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

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Produces;
import javax.enterprise.inject.spi.DeploymentException;
import javax.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import io.smallrye.jwt.KeyUtils;
import io.smallrye.jwt.SmallryeJwtUtils;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;

/**
 * A CDI provider for the JWTAuthContextInfo that obtains the necessary information from
 * MP config properties.
 */
@Dependent
public class JWTAuthContextInfoProvider {
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String NONE = "NONE";
    private static final String DEFAULT_GROUPS_SEPARATOR = " ";
    private static final Logger log = Logger.getLogger(JWTAuthContextInfoProvider.class);

    /**
     * Create JWTAuthContextInfoProvider with the public key and issuer
     *
     * @param publicKey the public key value
     * @param issuer the issuer
     * @return a new instance of JWTAuthContextInfoProvider
     */
    public static JWTAuthContextInfoProvider createWithKey(String publicKey, String issuer) {
        return create(publicKey, NONE, issuer);
    }

    /**
     * Create JWTAuthContextInfoProvider with the public key location and issuer
     *
     * @param publicKeyLocation the public key location
     * @param issuer the issuer
     * @return a new instance of JWTAuthContextInfoProvider
     */
    public static JWTAuthContextInfoProvider createWithKeyLocation(String publicKeyLocation, String issuer) {
        return create(NONE, publicKeyLocation, issuer);
    }

    private static JWTAuthContextInfoProvider create(String publicKey, String publicKeyLocation, String issuer) {
        JWTAuthContextInfoProvider provider = new JWTAuthContextInfoProvider();
        provider.mpJwtPublicKey = Optional.of(publicKey);
        provider.mpJwtLocation = Optional.of(publicKeyLocation);
        provider.mpJwtIssuer = issuer;

        provider.mpJwtRequireIss = Optional.of(Boolean.TRUE);
        provider.tokenHeader = AUTHORIZATION_HEADER;
        provider.tokenCookie = Optional.empty();
        provider.tokenKeyId = Optional.empty();
        provider.requireNamedPrincipal = Optional.of(Boolean.TRUE);
        provider.defaultSubClaim = Optional.empty();
        provider.subPath = Optional.empty();
        provider.defaultGroupsClaim = Optional.empty();
        provider.groupsPath = Optional.empty();
        provider.expGracePeriodSecs = Optional.of(60);
        provider.jwksRefreshInterval = Optional.empty();
        provider.whitelistAlgorithms = Optional.empty();
        provider.expectedAudience = Optional.empty();
        provider.groupsSeparator = DEFAULT_GROUPS_SEPARATOR;

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
    /**
     * @since 1.1
     */
    private Optional<String> mpJwtLocation;
    /**
     * Not part of the 1.1 release, but talked about.
     */
    @Inject
    @ConfigProperty(name = "mp.jwt.verify.requireiss", defaultValue = "true")
    private Optional<Boolean> mpJwtRequireIss;

    // SmallRye JWT specific properties
    /**
     * HTTP header which is expected to contain a JWT token, default value is 'Authorization'
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.token.header", defaultValue = AUTHORIZATION_HEADER)
    private String tokenHeader;

    /**
     * Cookie name containing a JWT token. This property is ignored unless the "smallrye.jwt.token.header" is set to 'Cookie'
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.token.cookie")
    private Optional<String> tokenCookie;

    /**
     * The key identifier ('kid'). If it is set then if the token contains 'kid' then both values must match. It will also be
     * used to
     * select a JWK key from a JWK set.
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.token.kid")
    private Optional<String> tokenKeyId;

    /**
     * Check that the JWT has at least one of 'sub', 'upn' or 'preferred_user_name' set. If not the JWT validation will
     * fail.
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.require.named-principal", defaultValue = "false")
    private Optional<Boolean> requireNamedPrincipal;

    /**
     * Default subject claim value. This property can be used to support the JWT tokens without a 'sub' claim.
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.claims.sub")
    private Optional<String> defaultSubClaim;

    /**
     * Path to the claim containing the sub. It starts from the top level JSON object and
     * can contain multiple segments where each segment represents a JSON object name only, example: "realm/sub".
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
     * JWK cache refresh interval in minutes. It will be ignored unless the 'mp.jwt.verify.publickey.location' property points
     * to the HTTPS URL based JWK set.
     * Note this property will only be used if no HTTP Cache-Control response header with a positive 'max-age' parameter value
     * is available.
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.jwks.refresh-interval", defaultValue = "60")
    private Optional<Integer> jwksRefreshInterval;

    /**
     * List of supported JSON Web Algorithm RSA and Elliptic Curve signing algorithms, default is RS256.
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.whitelist.algorithms")
    private Optional<String> whitelistAlgorithms;

    /**
     * The audience value(s) that identify valid recipient(s) of a JWT. Audience validation
     * will succeed, if any one of the provided values is equal to any one of the values of
     * the "aud" claim in the JWT. The config value should be specified as a comma-separated
     * list per MP Config requirements for a collection property.
     *
     * @since 2.0.3
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.verify.aud")
    Optional<Set<String>> expectedAudience;

    @Produces
    Optional<JWTAuthContextInfo> getOptionalContextInfo() {
        // Log the config values
        log.debugf("init, mpJwtPublicKey=%s, mpJwtIssuer=%s, mpJwtLocation=%s",
                mpJwtPublicKey.orElse("missing"), mpJwtIssuer, mpJwtLocation.orElse("missing"));
        /*
         * FIXME Due to a bug in MP-Config (https://github.com/wildfly-extras/wildfly-microprofile-config/issues/43) we need to
         * set all
         * values to "NONE" as Optional Strings are populated with a ConfigProperty.defaultValue if they are absent. Fix this
         * when MP-Config
         * is repaired.
         */
        if (NONE.equals(mpJwtPublicKey.get()) && NONE.equals(mpJwtLocation.get())) {
            log.debugf("Neither mpJwtPublicKey nor mpJwtLocation properties are configured,"
                    + " JWTAuthContextInfo will not be available");
            return Optional.empty();
        }

        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();
        // Look to MP-JWT values first
        decodeMpJwtPublicKey(contextInfo);

        if (mpJwtIssuer != null && !mpJwtIssuer.equals(NONE)) {
            contextInfo.setIssuedBy(mpJwtIssuer);
        } else {
            // If there is no expected issuer configured, don't validate it; new in MP-JWT 1.1
            contextInfo.setRequireIssuer(false);
        }

        // Default is to require iss claim
        contextInfo.setRequireIssuer(mpJwtRequireIss.orElse(true));

        // The MP-JWT location can be a PEM, JWK or JWKS
        if (mpJwtLocation.isPresent() && !NONE.equals(mpJwtLocation.get())) {
            contextInfo.setPublicKeyLocation(mpJwtLocation.get());
        }
        if (tokenHeader != null) {
            contextInfo.setTokenHeader(tokenHeader);
        }

        contextInfo.setTokenKeyId(tokenKeyId.orElse(null));
        contextInfo.setRequireNamedPrincipal(requireNamedPrincipal.orElse(null));
        SmallryeJwtUtils.setContextTokenCookie(contextInfo, tokenCookie);
        contextInfo.setDefaultSubjectClaim(defaultSubClaim.orElse(null));
        SmallryeJwtUtils.setContextSubPath(contextInfo, subPath);
        contextInfo.setDefaultGroupsClaim(defaultGroupsClaim.orElse(null));
        SmallryeJwtUtils.setContextGroupsPath(contextInfo, groupsPath);
        contextInfo.setExpGracePeriodSecs(expGracePeriodSecs.orElse(null));
        contextInfo.setJwksRefreshInterval(jwksRefreshInterval.orElse(null));
        SmallryeJwtUtils.setWhitelistAlgorithms(contextInfo, whitelistAlgorithms);
        contextInfo.setExpectedAudience(expectedAudience.orElse(null));
        contextInfo.setGroupsSeparator(groupsSeparator);

        return Optional.of(contextInfo);
    }

    protected void decodeMpJwtPublicKey(JWTAuthContextInfo contextInfo) {
        if (!mpJwtPublicKey.isPresent() || NONE.equals(mpJwtPublicKey.get())) {
            return;
        }

        // Need to decode what this is...
        try {
            RSAPublicKey pk = (RSAPublicKey) KeyUtils.decodeJWKSPublicKey(mpJwtPublicKey.get());
            contextInfo.setSignerKey(pk);
            log.debugf("mpJwtPublicKey parsed as JWK(S)");
        } catch (Exception e) {
            // Try as PEM key value
            log.debugf("mpJwtPublicKey failed as JWK(S), %s", e.getMessage());
            try {
                PublicKey pk = KeyUtils.decodePublicKey(mpJwtPublicKey.get());
                contextInfo.setSignerKey(pk);
                log.debugf("mpJwtPublicKey parsed as PEM");
            } catch (Exception e1) {
                throw new DeploymentException(e1);
            }
        }

    }

    public Optional<String> getMpJwtPublicKey() {
        return mpJwtPublicKey;
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

    public String getTokenHeader() {
        return tokenHeader;
    }

    public Optional<String> getTokenCookie() {
        return tokenCookie;
    }

    public Optional<String> getTokenKeyId() {
        return tokenKeyId;
    }

    public Optional<Integer> getExpGracePeriodSecs() {
        return expGracePeriodSecs;
    }

    public Optional<Integer> getJwksRefreshInterval() {
        return jwksRefreshInterval;
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

    public Optional<String> getWhitelistAlgorithms() {
        return whitelistAlgorithms;
    }

    public Optional<Set<String>> getExpectedAudience() {
        return expectedAudience;
    }

    @Produces
    @ApplicationScoped
    public JWTAuthContextInfo getContextInfo() {
        return getOptionalContextInfo().orElseThrow(throwException());
    }

    private static Supplier<IllegalStateException> throwException() {
        final String error = "JWTAuthContextInfo has not been initialized. Please make sure that either "
                + "'mp.jwt.verify.publickey' or 'mp.jwt.verify.publickey.location' properties are set.";
        return () -> new IllegalStateException(error);
    }
}
