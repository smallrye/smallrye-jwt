/*
 * Copyright (c) 2016-2017 Contributors to the Eclipse Foundation
 *
 *  See the NOTICE file(s) distributed with this work for additional
 *  information regarding copyright ownership.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  You may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package io.smallrye.jwt.auth.jaxrs;

import javax.annotation.Priority;
import javax.inject.Inject;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.ext.Provider;

import org.jboss.logging.Logger;

import java.io.IOException;

import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipal;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipalFactory;
import io.smallrye.jwt.auth.principal.ParseException;


/**
 * A JAX-RS ContainerRequestFilter prototype
 * TODO
 */
@Priority(Priorities.AUTHENTICATION)
@Provider
public class JWTAuthFilter implements ContainerRequestFilter {

    private static Logger logger = Logger.getLogger(JWTAuthFilter.class);

    @Inject
    private JWTAuthContextInfo authContextInfo;

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        String bearerToken = getBearerToken(requestContext);

        if (bearerToken != null) {
            try {
                JWTCallerPrincipal jwtPrincipal = validate(bearerToken);
                // Install the JWT principal as the caller
                final SecurityContext securityContext = requestContext.getSecurityContext();
                JWTSecurityContext jwtSecurityContext = new JWTSecurityContext(securityContext, jwtPrincipal);
                requestContext.setSecurityContext(jwtSecurityContext);
                logger.debugf("Success");
            }
            catch (Exception ex) {
                logger.warnf(ex, "Failed with ex=%s", ex.getMessage());
                requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
            }
        }
        else {
            logger.debug("Failed due to missing Authorization bearer token");
            requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
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
    String getBearerToken(ContainerRequestContext requestContext) {
        final String tokenHeaderName = authContextInfo.getTokenHeader();
        final String bearerValue;

        if ("Cookie".equals(tokenHeaderName)) {
            String tokenCookieName = authContextInfo.getTokenCookie();

            if (tokenCookieName == null) {
                tokenCookieName = "Bearer";
            }

            logger.debugf("tokenCookieName = %s", tokenCookieName);

            final Cookie tokenCookie = requestContext.getCookies().get(tokenCookieName);

            if (tokenCookie != null) {
                bearerValue = tokenCookie.getValue();
            } else {
                logger.debugf("tokenCookie %s was null", tokenCookieName);
                bearerValue = null;
            }
        } else {
            final String tokenHeader = requestContext.getHeaderString(tokenHeaderName);
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