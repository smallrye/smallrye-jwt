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

import java.io.IOException;
import java.security.Principal;

import javax.annotation.Priority;
import javax.inject.Inject;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.SecurityContext;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.logging.Logger;

import io.smallrye.jwt.auth.AbstractBearerTokenExtractor;
import io.smallrye.jwt.auth.cdi.PrincipalProducer;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;

/**
 * A JAX-RS ContainerRequestFilter prototype
 */
@PreMatching
@Priority(Priorities.AUTHENTICATION)
public class JWTAuthenticationFilter implements ContainerRequestFilter {

    private static Logger logger = Logger.getLogger(JWTAuthenticationFilter.class);

    @Inject
    private JWTAuthContextInfo authContextInfo;

    @Inject
    private PrincipalProducer producer;

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        final SecurityContext securityContext = requestContext.getSecurityContext();
        final Principal principal = securityContext.getUserPrincipal();

        if (!(principal instanceof JsonWebToken)) {
            AbstractBearerTokenExtractor extractor = new BearerTokenExtractor(requestContext, authContextInfo);
            String bearerToken = extractor.getBearerToken();

            if (bearerToken != null) {
                try {
                    JsonWebToken jwtPrincipal = extractor.validate(bearerToken);
                    producer.setJsonWebToken(jwtPrincipal);

                    // Install the JWT principal as the caller
                    JWTSecurityContext jwtSecurityContext = new JWTSecurityContext(securityContext, jwtPrincipal);
                    requestContext.setSecurityContext(jwtSecurityContext);
                    logger.debugf("Success");
                } catch (Exception e) {
                    logger.warnf(e, "Unable to parse/validate JWT: %s", e.getMessage());
                }
            }
        }
    }

    private static class BearerTokenExtractor extends AbstractBearerTokenExtractor {
        private final ContainerRequestContext requestContext;

        BearerTokenExtractor(ContainerRequestContext requestContext, JWTAuthContextInfo authContextInfo) {
            super(authContextInfo);
            this.requestContext = requestContext;
        }

        @Override
        protected String getHeaderValue(String headerName) {
            return requestContext.getHeaderString(headerName);
        }

        @Override
        protected String getCookieValue(String cookieName) {
            Cookie tokenCookie = requestContext.getCookies().get(cookieName);

            if (tokenCookie != null) {
                return tokenCookie.getValue();
            }
            return null;
        }
    }
}