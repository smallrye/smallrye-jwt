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

import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.PreMatching;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.SecurityContext;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jose4j.lang.UnresolvableKeyException;

import io.smallrye.jwt.auth.AbstractBearerTokenExtractor;
import io.smallrye.jwt.auth.cdi.PrincipalProducer;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTParser;
import io.smallrye.jwt.auth.principal.ParseException;

/**
 * A JAX-RS ContainerRequestFilter prototype
 */
@PreMatching
@Priority(Priorities.AUTHENTICATION)
public class JWTAuthenticationFilter implements ContainerRequestFilter {

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
                } catch (ParseException e) {
                    if (e.getCause() instanceof UnresolvableKeyException) {
                        JAXRSLogging.log.noUsableKey();
                        throw new InternalServerErrorException(e);
                    } else {
                        JAXRSLogging.log.unableToValidateBearerToken(e);
                        throw new NotAuthorizedException(e);
                    }
                } catch (Exception e) {
                    JAXRSLogging.log.unableToValidateBearerToken(e);
                    throw new InternalServerErrorException(e);
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
