/*
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

import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;

/**
 * Common functionality for classes extracting Bearer tokens from HTTP request
 * headers (including Cookie) and converting the token string to a
 * {@link JsonWebToken}.
 *
 *
 * @author Michael Edgar {@literal <michael@xlate.io>}
 */
public abstract class AbstractBearerTokenExtractor {

    protected static final String AUTHORIZATION_HEADER = "Authorization";
    protected static final String COOKIE_HEADER = "Cookie";
    protected static final String BEARER = "Bearer";
    protected static final String BEARER_SCHEME_PREFIX = BEARER + ' ';

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
        final boolean fallbackToHeader = authContextInfo.isAlwaysCheckAuthorization();
        AuthLogging.log.tokenHeaderName(tokenHeaderName);

        final String bearerValue;

        if (COOKIE_HEADER.equals(tokenHeaderName)) {
            String intermediateBearerValue = getBearerTokenCookie();
            if (intermediateBearerValue == null && fallbackToHeader) {
                bearerValue = getBearerTokenAuthHeader();
            } else {
                bearerValue = intermediateBearerValue;
            }
        } else if (AUTHORIZATION_HEADER.equals(tokenHeaderName)) {
            bearerValue = getBearerTokenAuthHeader();
        } else {
            String customHeaderValue = getHeaderValue(tokenHeaderName);

            if (customHeaderValue == null) {
                AuthLogging.log.headerIsNull(tokenHeaderName);
            } else {
                String customHeaderSchemeValue = getTokenWithConfiguredScheme(customHeaderValue);
                if (customHeaderSchemeValue != null) {
                    customHeaderValue = customHeaderSchemeValue;
                }
            }
            bearerValue = customHeaderValue;
        }

        return bearerValue;
    }

    private String getBearerTokenCookie() {
        String tokenCookieName = authContextInfo.getTokenCookie();

        if (tokenCookieName == null) {
            tokenCookieName = BEARER;
        }

        AuthLogging.log.tokenCookieName(tokenCookieName);

        String bearerValue = getCookieValue(tokenCookieName);

        if (bearerValue == null) {
            AuthLogging.log.cookieIsNull(tokenCookieName);
        }

        return bearerValue;
    }

    private String getBearerTokenAuthHeader() {
        final String tokenHeader = getHeaderValue(AUTHORIZATION_HEADER);
        final String bearerValue;

        if (tokenHeader != null) {
            final String token = getTokenWithConfiguredScheme(tokenHeader);
            if (token != null) {
                bearerValue = token;
            } else {
                AuthLogging.log.authHeaderDoesNotContainBearerPrefix();
                bearerValue = null;
            }
        } else {
            AuthLogging.log.authHeaderIsNull();
            bearerValue = null;
        }

        return bearerValue;
    }

    private String getTokenWithConfiguredScheme(String tokenHeader) {
        for (final String scheme : authContextInfo.getTokenSchemes()) {
            final String schemePrefix = scheme + " ";
            if (isTokenScheme(tokenHeader, schemePrefix)) {
                return tokenHeader.substring(schemePrefix.length());
            }
        }
        return null;
    }

    private static boolean isTokenScheme(String headerValue, String schemePrefix) {
        if (headerValue.length() < schemePrefix.length()) {
            return false;
        }

        String scheme = headerValue.substring(0, schemePrefix.length());

        return schemePrefix.equalsIgnoreCase(scheme);
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
