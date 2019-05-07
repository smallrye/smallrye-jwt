package io.smallrye.jwt.auth.principal;


import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.eclipse.microprofile.jwt.Claims;
import org.jboss.logging.Logger;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.jose4j.lang.JoseException;

/**
 * Default JWT token validator 
 *
 */
public class DefaultJWTTokenParser {
	private static Logger logger = Logger.getLogger(DefaultJWTTokenParser.class);
	private static final String ROLE_MAPPINGS = "roleMappings";
	
    private HttpsJwks httpsJwks;

    public JwtContext parse(final String token, final JWTAuthContextInfo authContextInfo) throws ParseException {

        try {
            JwtConsumerBuilder builder = new JwtConsumerBuilder()
                    .setRequireExpirationTime()
                    .setRequireSubject()
                    .setSkipDefaultAudienceValidation()
                    .setJwsAlgorithmConstraints(
                            new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST,
                                                     AlgorithmIdentifiers.RSA_USING_SHA256));

            if (authContextInfo.isRequireIssuer()) {
                builder.setExpectedIssuer(true, authContextInfo.getIssuedBy());
            } else {
                builder.setExpectedIssuer(false, null);
            }
            if (authContextInfo.getSignerKey() != null) {
                builder.setVerificationKey(authContextInfo.getSignerKey());
            } else if (authContextInfo.isFollowMpJwt11Rules()) {
                builder.setVerificationKeyResolver(new KeyLocationResolver(authContextInfo.getJwksUri()));
            } else {
                final List<JsonWebKey> jsonWebKeys = loadJsonWebKeys(authContextInfo);
                builder.setVerificationKeyResolver(new JwksVerificationKeyResolver(jsonWebKeys));
            }

            if (authContextInfo.getExpGracePeriodSecs() > 0) {
                builder.setAllowedClockSkewInSeconds(authContextInfo.getExpGracePeriodSecs());
            } else {
                builder.setEvaluationTime(NumericDate.fromSeconds(0));
            }

            JwtConsumer jwtConsumer = builder.build();
            JwtContext jwtContext = jwtConsumer.process(token);
            //  Validate the JWT and process it to the Claims
            jwtConsumer.processContext(jwtContext);
            
            JwtClaims claimsSet = jwtContext.getJwtClaims();
            claimsSet.setClaim(Claims.raw_token.name(), token);
            if (!claimsSet.hasClaim(Claims.groups.name()) && authContextInfo.getDefaultGroups() != null) {
                claimsSet.setClaim(Claims.groups.name(), Collections.singletonList(authContextInfo.getDefaultGroups()));
            }
            // Process the rolesMapping claim
            if (claimsSet.hasClaim(ROLE_MAPPINGS)) {
                try {
                    @SuppressWarnings("unchecked")
                    Map<String, String> rolesMapping = claimsSet.getClaimValue(ROLE_MAPPINGS, Map.class);
                    List<String> groups = claimsSet.getStringListClaimValue(Claims.groups.name());
                    List<String> allGroups = new ArrayList<>(groups);
                    for (String key : rolesMapping.keySet()) {
                        // If the key group is in groups list, add the mapped role
                        if (groups.contains(key)) {
                            String toRole = rolesMapping.get(key);
                            allGroups.add(toRole);
                        }
                    }
                    // Replace the groups with the original groups + mapped roles
                    claimsSet.setStringListClaim("groups", allGroups);
                    logger.infof("Updated groups to: %s", allGroups);
                } catch (Exception e) {
                    logger.warnf(e, "Failed to access rolesMapping claim");
                }
            }
            
            return jwtContext;
        } catch (InvalidJwtException e) {
            logger.warnf("Token is invalid: %s", e.getMessage());
            throw new ParseException("Failed to verify token", e);
        }

    }
    
    protected List<JsonWebKey> loadJsonWebKeys(JWTAuthContextInfo authContextInfo) {
        synchronized (this) {
            if (authContextInfo.getJwksUri() == null) {
                return Collections.emptyList();
            }

            if (httpsJwks == null) {
                httpsJwks = new HttpsJwks(authContextInfo.getJwksUri());
                httpsJwks.setDefaultCacheDuration(authContextInfo.getJwksRefreshInterval().longValue() * 60L);
            }
        }

        try {
            return httpsJwks.getJsonWebKeys().stream()
                    .filter(jsonWebKey -> "sig".equals(jsonWebKey.getUse())) // only signing keys are relevant
                    .filter(jsonWebKey -> "RS256".equals(jsonWebKey.getAlgorithm())) // MP-JWT dictates RS256 only
                    .collect(Collectors.toList());
        } catch (IOException | JoseException e) {
            throw new IllegalStateException(String.format("Unable to fetch JWKS from %s.",
                authContextInfo.getJwksUri()), e);
        }
    }
}
