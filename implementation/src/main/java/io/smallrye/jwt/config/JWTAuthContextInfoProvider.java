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

import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Optional;
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
    private static final Logger log = Logger.getLogger(JWTAuthContextInfoProvider.class);

    public JWTAuthContextInfoProvider() {

    }

    /**
     * Create JWTAuthContextInfoProvider with the public key and issuer
     * 
     * @param publicKey the public key value
     * @param issuer the issuer
     * @return
     */
    public static JWTAuthContextInfoProvider createWithKey(String publicKey, String issuer) {
        return create(publicKey, NONE, issuer);
    }

    /**
     * Create JWTAuthContextInfoProvider with the public key location and issuer
     * 
     * @param publicKeyLocation the public key location
     * @param issuer the issuer
     * @return
     */
    public static JWTAuthContextInfoProvider createWithKeyLocation(String publicKeyLocation, String issuer) {
        return create(NONE, publicKeyLocation, issuer);
    }

    private static JWTAuthContextInfoProvider create(String publicKey, String publicKeyLocation, String issuer) {
        JWTAuthContextInfoProvider provider = new JWTAuthContextInfoProvider();
        provider.mpJwtPublicKey = Optional.of(publicKey);
        provider.mpJwtLocation = Optional.of(publicKeyLocation);
        provider.mpJwtIssuer = issuer;
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
     * JSON path to the claim containing the sub. It starts from the top level JSON object and
     * can contain multiple segments where each segment represents a JSON object name only, example: "realm/sub".
     * This property can be used if a token has no 'sub' claim but has the sub set in a different claim.
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.sub.path")
    private Optional<String> subPath;
    /**
     * Default groups claim value. This property can be used to support the JWT tokens without a 'groups' claim.
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.claims.groups")
    private Optional<String> defaultGroupsClaim;
    /**
     * JSON path to the claim containing an array of groups. It starts from the top level JSON object and
     * can contain multiple segments where each segment represents a JSON object name only, example: "realm/groups".
     * This property can be used if a token has no 'groups' claim but has the groups set in a different claim.
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.groups.path")
    private Optional<String> groupsPath;
    @Inject
    @ConfigProperty(name = "smallrye.jwt.expiration.grace", defaultValue = "60")
    private Optional<Integer> expGracePeriodSecs;
    /**
     * List of algorithms to whitelist JWT validation based on jose4j algorithms
     * list org.jose4j.jws.AlgorithmIdentifiers.
     */
    @Inject
    @ConfigProperty(name = "smallrye.jwt.whitelist.algorithms")
    private Optional<String> whitelistAlgorithms;

    @Produces
    @ApplicationScoped
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
        if (mpJwtPublicKey.isPresent() && !NONE.equals(mpJwtPublicKey.get())) {
            decodeMpJwtPublicKey(contextInfo);
        }

        if (mpJwtIssuer != null && !mpJwtIssuer.equals(NONE)) {
            contextInfo.setIssuedBy(mpJwtIssuer);
        } else {
            // If there is no expected issuer configured, don't validate it; new in MP-JWT 1.1
            contextInfo.setRequireIssuer(false);
        }

        if (mpJwtRequireIss != null && mpJwtRequireIss.isPresent()) {
            contextInfo.setRequireIssuer(mpJwtRequireIss.get());
        } else {
            // Default is to require iss claim
            contextInfo.setRequireIssuer(true);
        }

        // The MP-JWT location can be a PEM, JWK or JWKS
        if (mpJwtLocation.isPresent() && !NONE.equals(mpJwtLocation.get())) {
            setMpJwtLocation(contextInfo);
        }
        if (tokenHeader != null) {
            contextInfo.setTokenHeader(tokenHeader);
        }
        if (requireNamedPrincipal != null && requireNamedPrincipal.isPresent()) {
            contextInfo.setRequireNamedPrincipal(requireNamedPrincipal.get());
        }
        SmallryeJwtUtils.setContextTokenCookie(contextInfo, tokenCookie);
        if (defaultSubClaim != null && defaultSubClaim.isPresent()) {
            contextInfo.setDefaultSubClaim(defaultSubClaim.get());
        }
        SmallryeJwtUtils.setContextSubPath(contextInfo, subPath);
        if (defaultGroupsClaim != null && defaultGroupsClaim.isPresent()) {
            contextInfo.setDefaultGroupsClaim(defaultGroupsClaim.get());
        }
        SmallryeJwtUtils.setContextGroupsPath(contextInfo, groupsPath);

        if (expGracePeriodSecs != null && expGracePeriodSecs.isPresent()) {
            contextInfo.setExpGracePeriodSecs(expGracePeriodSecs.get());
        }

        SmallryeJwtUtils.setWhitelistAlgorithms(contextInfo, whitelistAlgorithms);

        return Optional.of(contextInfo);
    }

    protected void setMpJwtLocation(JWTAuthContextInfo contextInfo) {
        contextInfo.setJwksUri(mpJwtLocation.get());
        contextInfo.setFollowMpJwt11Rules(true);
    }

    protected void decodeMpJwtPublicKey(JWTAuthContextInfo contextInfo) {
        // Need to decode what this is...
        try {
            RSAPublicKey pk = (RSAPublicKey) KeyUtils.decodeJWKSPublicKey(mpJwtPublicKey.get());
            contextInfo.setSignerKey(pk);
            log.debugf("mpJwtPublicKey parsed as JWK(S)");
        } catch (Exception e) {
            // Try as PEM key value
            log.debugf("mpJwtPublicKey failed as JWK(S), %s", e.getMessage());
            try {
                RSAPublicKey pk = (RSAPublicKey) KeyUtils.decodePublicKey(mpJwtPublicKey.get());
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

    public Optional<String> getDefaultGroupsClaim() {
        return defaultGroupsClaim;
    }

    public Optional<String> getGroupsPath() {
        return groupsPath;
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
