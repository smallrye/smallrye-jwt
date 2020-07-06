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
package io.smallrye.jwt.auth.mechanism;

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

import org.eclipse.microprofile.jwt.JsonWebToken;

import io.smallrye.jwt.auth.AbstractBearerTokenExtractor;
import io.smallrye.jwt.auth.cdi.PrincipalProducer;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTParser;

/**
 * A JAX-RS HttpAuthenticationMechanism prototype
 * TODO - JavaDoc and tests
 */
@ApplicationScoped
public class JWTHttpAuthenticationMechanism implements HttpAuthenticationMechanism {

    @Inject
    private JWTAuthContextInfo authContextInfo;

    @Inject
    private JWTParser jwtParser;

    @Inject
    private PrincipalProducer producer;

    public JWTHttpAuthenticationMechanism() {
    }

    public JWTHttpAuthenticationMechanism(JWTAuthContextInfo authContextInfo,
            JWTParser jwtParser,
            PrincipalProducer producer) {
        this.authContextInfo = authContextInfo;
        this.jwtParser = jwtParser;
        this.producer = producer;
    }

    @Override
    public AuthenticationStatus validateRequest(HttpServletRequest request,
            HttpServletResponse response,
            HttpMessageContext httpMessageContext)
            throws AuthenticationException {

        AbstractBearerTokenExtractor extractor = new BearerTokenExtractor(request, authContextInfo);
        String bearerToken = extractor.getBearerToken();

        if (bearerToken != null) {
            try {
                JsonWebToken jwtPrincipal = jwtParser.parse(bearerToken);
                producer.setJsonWebToken(jwtPrincipal);
                Set<String> groups = jwtPrincipal.getGroups();
                MechanismLogging.log.success();
                return httpMessageContext.notifyContainerAboutLogin(jwtPrincipal, groups);
            } catch (Exception e) {
                MechanismLogging.log.unableToValidateBearerToken(e);
                return httpMessageContext.responseUnauthorized();
            }
        } else {
            MechanismLogging.log.noUsableBearerTokenFound();
            return httpMessageContext.isProtected() ? httpMessageContext.responseUnauthorized()
                    : httpMessageContext.doNothing();
        }
    }

    private static class BearerTokenExtractor extends AbstractBearerTokenExtractor {
        private final HttpServletRequest request;

        BearerTokenExtractor(HttpServletRequest request, JWTAuthContextInfo authContextInfo) {
            super(authContextInfo);
            this.request = request;
        }

        @Override
        protected String getHeaderValue(String headerName) {
            return request.getHeader(headerName);
        }

        @Override
        protected String getCookieValue(String cookieName) {
            Cookie[] cookies = request.getCookies();
            Cookie tokenCookie = null;

            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if (cookieName.equals(cookie.getName())) {
                        tokenCookie = cookie;
                        break;
                    }
                }
            }

            if (tokenCookie != null) {
                return tokenCookie.getValue();
            }

            return null;
        }
    }
}