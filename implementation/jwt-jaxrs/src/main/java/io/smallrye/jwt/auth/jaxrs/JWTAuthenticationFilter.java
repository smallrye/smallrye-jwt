/*
 *   Copyright 2019 Red Hat, Inc, and individual contributors.
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
package io.smallrye.jwt.auth.jaxrs;

import java.io.IOException;
import java.security.Principal;

import javax.annotation.Priority;
import javax.inject.Inject;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;

import org.eclipse.microprofile.jwt.JsonWebToken;

import io.smallrye.jwt.auth.AbstractBearerTokenExtractor;
import io.smallrye.jwt.auth.cdi.PrincipalProducer;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTParser;

/**
 * A JAX-RS ContainerRequestFilter prototype
 */
@PreMatching
@Priority(Priorities.AUTHENTICATION)
public class JWTAuthenticationFilter implements ContainerRequestFilter {
    public static final String HAS_JWT = JWTAuthenticationFilter.class.getName() + ".has.jwt";

    @Inject
    private JWTAuthContextInfo authContextInfo;
    @Inject
    private JWTParser jwtParser;
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
                    JsonWebToken jwtPrincipal = jwtParser.parse(bearerToken);
                    producer.setJsonWebToken(jwtPrincipal);

                    // Install the JWT principal as the caller
                    JWTSecurityContext jwtSecurityContext = new JWTSecurityContext(securityContext, jwtPrincipal);
                    requestContext.setSecurityContext(jwtSecurityContext);
                    JAXRSLogging.log.success();
                } catch (Exception e) {
                    JAXRSLogging.log.unableParseJWT(e);
                    throw new NotAuthorizedException(Response.status(Response.Status.UNAUTHORIZED).build());
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
