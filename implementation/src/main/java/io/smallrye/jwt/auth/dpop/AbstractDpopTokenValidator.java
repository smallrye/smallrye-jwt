/*
 * Copyright 2020 Red Hat, Inc, and individual contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package io.smallrye.jwt.auth.dpop;

import static org.jose4j.jwa.AlgorithmConstraints.ConstraintType.PERMIT;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.Validator;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.resolvers.EmbeddedJwkVerificationKeyResolver;
import org.jose4j.lang.HashUtil;
import org.jose4j.lang.JoseException;

import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.ParseException;

/**
 * Common functionality for classes implementing DPoP token proofing using
 * HTTP request headers and a valid DPoP-bound {@link JsonWebToken}.
 *
 * @author Aaron Coburn {@literal <acoburn@apache.org>}
 */
public abstract class AbstractDpopTokenValidator {

    protected static final String DPOP_HEADER = "DPoP";
    protected static final String DPOP_HTTP_URI_CLAIM = "htu";
    protected static final String DPOP_HTTP_METHOD_CLAIM = "htm";
    protected static final String DPOP_JWT_TYPE = "dpop+jwt";
    protected static final String JSON_WEB_KEY_THUMBPRINT = "jkt";

    private final JWTAuthContextInfo authContextInfo;

    protected AbstractDpopTokenValidator(JWTAuthContextInfo authContextInfo) {
        this.authContextInfo = authContextInfo;
    }

    public void verify(JsonWebToken accessToken) throws ParseException {
        final String dpop = getDpopHeaderValue();
        final String thumbprint = getDpopKeyThumbprint(accessToken);
        // DPoP validation is only relevant for access tokens with a bound confirmation key.
        if (thumbprint != null) {
            if (dpop != null) {
                final JwtConsumer parser = new JwtConsumerBuilder()
                        .setRequireJwtId()
                        .setExpectedType(true, DPOP_JWT_TYPE)
                        .setJwsAlgorithmConstraints(new AlgorithmConstraints(PERMIT,
                                authContextInfo.getSignatureAlgorithm().getAlgorithm()))
                        .setVerificationKeyResolver(new EmbeddedJwkVerificationKeyResolver())
                        .setRequireIssuedAt().setAllowedClockSkewInSeconds(authContextInfo.getExpGracePeriodSecs())
                        .setExpectedIssuer(false, null)
                        .registerValidator(htuValidator(getRequestUri()))
                        .registerValidator(htmValidator(getRequestMethod()))
                        .registerValidator(thumbprintValidator(thumbprint))
                        .build();
                try {
                    parser.process(dpop);
                } catch (InvalidJwtException e) {
                    DpopLogging.log.invalidDpopToken();
                    throw DpopMessages.msg.failedToVerifyDpopToken(e);
                }
            } else {
                DpopLogging.log.missingDpopToken();
                throw DpopMessages.msg.missingDpopProof();
            }
        } else {
            DpopLogging.log.missingDpopKeyBinding();
            throw DpopMessages.msg.missingDpopKeyBinding();
        }
    }

    /**
     * Retrieve the DPoP-bound key thumbprint from the access token's confirmation claim.
     *
     * @param accessToken the access token
     * @return the thumbprint of the DPoP-bound key, if one exists
     */
    protected String getDpopKeyThumbprint(JsonWebToken accessToken) {
        final Object cnf = accessToken.getClaim(Claims.cnf.name());
        if (cnf instanceof Map) {
            final Object jkt = ((Map) cnf).get(JSON_WEB_KEY_THUMBPRINT);
            if (jkt instanceof String) {
                return (String) jkt;
            }
        }
        return null;
    }

    /**
     * Retrieve an HTTP DPoP header value.
     *
     * @return value of the header
     */
    protected abstract String getDpopHeaderValue();

    /**
     * Retrieve the HTTP request URI.
     *
     * @return the HTTP request URI
     */
    protected abstract String getRequestUri();

    /**
     * Retrieve the HTTP method.
     *
     * @return the HTTP method
     */
    protected abstract String getRequestMethod();

    /**
     * Validate the htu (HTTP URI) claim in the DPoP token.
     *
     * @param uri the HTTP request URI
     */
    static Validator htuValidator(String uri) {
        return ctx -> {
            final JwtClaims claims = ctx.getJwtClaims();
            if (!claims.hasClaim(DPOP_HTTP_URI_CLAIM)) {
                return "Missing required htu claim in DPoP token";
            }
            if (!compareUrls(uri, claims.getClaimValueAsString(DPOP_HTTP_URI_CLAIM))) {
                return "Incorrect htu claim";
            }
            return null;
        };
    }

    /**
     * Validate the htm (HTTP Method) claim in the DPoP token.
     *
     * @param method the HTTP method
     */
    static Validator htmValidator(String method) {
        return ctx -> {
            final JwtClaims claims = ctx.getJwtClaims();
            if (!claims.hasClaim(DPOP_HTTP_METHOD_CLAIM)) {
                return "Missing required htm claim in DPoP token";
            }

            if (!method.equalsIgnoreCase(claims.getClaimValueAsString(DPOP_HTTP_METHOD_CLAIM))) {
                return "Incorrect htm claim";
            }
            return null;
        };
    }

    /**
     * Validate that the embedded public key matches the provided thumbprint.
     * 
     * @param thumbprint the thumbprint of the expected public key
     */
    static Validator thumbprintValidator(String thumbprint) {
        return ctx -> {
            try {
                for (JsonWebStructure jose : ctx.getJoseObjects()) {
                    if (thumbprint.equals(jose.getJwkHeader().calculateBase64urlEncodedThumbprint(HashUtil.SHA_256))) {
                        return null;
                    }
                }
            } catch (JoseException ex) {
                return "Could not calculate SHA-256 thumbprint of embedded DPoP key: " + ex.getMessage();
            }
            return "Mismatched public key thumbprint: " + thumbprint;
        };
    }

    /**
     * Compare two URLs, ignoring case and any query parameters.
     *
     * @param url1 the first URL
     * @param url2 the second URL
     * @return true if the two URLs are equivalent; otherwise, return false
     */
    static boolean compareUrls(String url1, String url2) {
        if (url1 != null && url2 != null) {
            if (url1.equalsIgnoreCase(url2)) {
                return true;
            }
            // If a simple comparison was inconclusive, parse both into URI objects
            try {
                final URI uri1 = new URI(url1);
                final URI uri2 = new URI(url2);
                return uri1.getScheme().equalsIgnoreCase(uri2.getScheme())
                        && uri1.getAuthority().equalsIgnoreCase(uri2.getAuthority())
                        && uri1.getPath().equalsIgnoreCase(uri2.getPath());
            } catch (URISyntaxException ex) {
                DpopLogging.log.invalidRequestUrl(ex.getMessage());
            }
        }
        return false;
    }
}
