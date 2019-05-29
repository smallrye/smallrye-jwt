/**
 * Copyright 2019 Red Hat, Inc, and individual contributors.
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
package io.smallrye.jwt.auth;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.logging.Logger;

import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipal;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipalFactory;
import io.smallrye.jwt.auth.principal.ParseException;

/**
 * Common functionality for classes extracting Bearer tokens from HTTP request
 * headers (including Cookie) and converting the token string to a
 * {@link JsonWebToken}.
 *
 *
 * @author Michael Edgar {@literal <michael@xlate.io>}
 */
public abstract class AbstractBearerTokenExtractor {

    protected final static String AUTHORIZATION_HEADER = "Authorization";
    protected final static String COOKIE_HEADER = "Cookie";
    protected final static String BEARER = "Bearer";
    protected final static String BEARER_SCHEME_PREFIX = BEARER + ' ';
    private static Logger logger = Logger.getLogger(AbstractBearerTokenExtractor.class);

    private final JWTAuthContextInfo authContextInfo;

    protected AbstractBearerTokenExtractor(JWTAuthContextInfo authContextInfo) {
        this.authContextInfo = authContextInfo;
    }

    /**
     * Find a JWT Bearer token in the request by referencing the configurations
     * found in the {@link JWTAuthContextInfo}. The resulting token may be found
     * in a cookie or another HTTP header, either explicitly configured or the
     * default 'Authorization' header.
     *
     * @return a JWT Bearer token or null if not found
     */
    public String getBearerToken() {
        final String tokenHeaderName = authContextInfo.getTokenHeader();
        logger.debugf("tokenHeaderName = %s", tokenHeaderName);

        final String bearerValue;

        if (COOKIE_HEADER.equals(tokenHeaderName)) {
            String tokenCookieName = authContextInfo.getTokenCookie();

            if (tokenCookieName == null) {
                tokenCookieName = BEARER;
            }

            logger.debugf("tokenCookieName = %s", tokenCookieName);

            bearerValue = getCookieValue(tokenCookieName);

            if (bearerValue == null) {
                logger.debugf("Cookie %s was null", tokenCookieName);
            }
        } else if (AUTHORIZATION_HEADER.equals(tokenHeaderName)) {
            final String tokenHeader = getHeaderValue(tokenHeaderName);

            if (tokenHeader != null) {
                if (isBearerScheme(tokenHeader)) {
                    bearerValue = tokenHeader.substring(BEARER_SCHEME_PREFIX.length());
                } else {
                    logger.debugf("Authorization header does not contain a Bearer prefix");
                    bearerValue = null;
                }
            } else {
                logger.debugf("Authorization header was null");
                bearerValue = null;
            }
        } else {
            bearerValue = getHeaderValue(tokenHeaderName);

            if (bearerValue == null) {
                logger.debugf("Header %s was null", tokenHeaderName);
            }
        }

        return bearerValue;
    }

    private static boolean isBearerScheme(String authorizationHeader) {
        if (authorizationHeader.length() < BEARER_SCHEME_PREFIX.length()) {
            return false;
        }

        String scheme = authorizationHeader.substring(0, BEARER_SCHEME_PREFIX.length());

        return BEARER_SCHEME_PREFIX.equalsIgnoreCase(scheme);
    }

    public JsonWebToken validate(String bearerToken) throws ParseException {
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JWTCallerPrincipal callerPrincipal = factory.parse(bearerToken, authContextInfo);
        return callerPrincipal;
    }

    /**
     * Retrieve an HTTP request header by name.
     *
     * @param headerName name of the header
     * @return value of the header
     */
    protected abstract String getHeaderValue(String headerName);

    /**
     * Retrieve an HTTP request cookie value by name.
     *
     * @param cookieName name of the cookie
     * @return value of the cookie
     */
    protected abstract String getCookieValue(String cookieName);

}
