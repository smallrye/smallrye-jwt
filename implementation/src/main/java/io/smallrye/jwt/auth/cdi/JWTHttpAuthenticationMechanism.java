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
package io.smallrye.jwt.auth.cdi;

import java.util.Set;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.security.enterprise.AuthenticationException;
import javax.security.enterprise.AuthenticationStatus;
import javax.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import javax.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.logging.Logger;

import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipal;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipalFactory;
import io.smallrye.jwt.auth.principal.ParseException;


/**
 * A JAX-RS HttpAuthenticationMechanism prototype
 * TODO - JavaDoc and tests
 */
@ApplicationScoped
public class JWTHttpAuthenticationMechanism implements HttpAuthenticationMechanism {

    private static Logger logger = Logger.getLogger(JWTHttpAuthenticationMechanism.class);

    @Inject
    private JWTAuthContextInfo authContextInfo;

    @Inject
    private PrincipalProducer producer;

    @Override
    public AuthenticationStatus validateRequest(HttpServletRequest request,
                                                HttpServletResponse response,
                                                HttpMessageContext httpMessageContext)
                                            throws AuthenticationException {
        String bearerToken = getBearerToken(request);

        if (bearerToken != null) {
            try {
                JWTCallerPrincipal jwtPrincipal = validate(bearerToken);
                producer.setJsonWebToken(jwtPrincipal);
                Set<String> groups = jwtPrincipal.getGroups();
                logger.debugf("Success");
                return httpMessageContext.notifyContainerAboutLogin(jwtPrincipal, groups);
            } catch (Exception e) {
                logger.warnf(e, "Unable to validate bearer token: %s", e.getMessage());
                return httpMessageContext.responseUnauthorized();
            }
        } else {
            logger.debug("No usable bearer token was found in the request, continuing unauthenticated");
            return httpMessageContext.doNothing();
        }
    }

    /**
     * Find a JWT Bearer token in the request by referencing the configurations found
     * in the {@link JWTAuthContextInfo}. The resulting token may be found in a cookie
     * or another HTTP header, either explicitly configured or the default 'Authorization'
     * header.
     *
     * @param requestContext current request
     * @return a JWT Bearer token or null if not found
     */
    //TODO: consolidate with common logic found in JWTAuthFilter#getBearerToken if possible
    String getBearerToken(HttpServletRequest request) {
        final String tokenHeaderName = authContextInfo.getTokenHeader();
        final String bearerValue;

        if ("Cookie".equals(tokenHeaderName)) {
            String tokenCookieName = authContextInfo.getTokenCookie();

            if (tokenCookieName == null) {
                tokenCookieName = "Bearer";
            }

            logger.debugf("tokenCookieName = %s", tokenCookieName);
            Cookie[] cookies = request.getCookies();
            Cookie tokenCookie = null;

            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if (tokenCookieName.equals(cookie.getName())) {
                        tokenCookie = cookie;
                        break;
                    }
                }
            }

            if (tokenCookie != null) {
                bearerValue = tokenCookie.getValue();
            } else {
                logger.debugf("tokenCookie %s was null", tokenCookieName);
                bearerValue = null;
            }
        } else {
            final String tokenHeader = request.getHeader(tokenHeaderName);
            logger.debugf("tokenHeaderName = %s", tokenHeaderName);

            if (tokenHeader != null && tokenHeader.startsWith("Bearer ")) {
                bearerValue = tokenHeader.substring("Bearer ".length());
            } else {
                logger.debugf("tokenHeader %s was null", tokenHeaderName);
                bearerValue = null;
            }
        }

        return bearerValue;
    }

    protected JWTCallerPrincipal validate(String bearerToken) throws ParseException {
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JWTCallerPrincipal callerPrincipal = factory.parse(bearerToken, authContextInfo);
        return callerPrincipal;
    }
}