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

import static jakarta.security.enterprise.identitystore.IdentityStore.ValidationType.PROVIDE_GROUPS;

import java.io.IOException;
import java.util.Set;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.security.enterprise.AuthenticationException;
import jakarta.security.enterprise.AuthenticationStatus;
import jakarta.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import jakarta.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import jakarta.security.enterprise.identitystore.IdentityStore;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jose4j.lang.UnresolvableKeyException;

import io.smallrye.jwt.auth.AbstractBearerTokenExtractor;
import io.smallrye.jwt.auth.cdi.PrincipalProducer;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTParser;
import io.smallrye.jwt.auth.principal.ParseException;

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

    @Inject
    private Instance<IdentityStore> identityStores;

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
                String name = jwtPrincipal.getName();
                for (IdentityStore identityStore : identityStores) {
                    if (identityStore.validationTypes().contains(PROVIDE_GROUPS)) {
                        CredentialValidationResult credentialValidationResult = new CredentialValidationResult(name, groups);
                        Set<String> callerGroups = identityStore.getCallerGroups(credentialValidationResult);
                        groups.addAll(callerGroups);
                    }
                }
                MechanismLogging.log.success();
                return httpMessageContext.notifyContainerAboutLogin(jwtPrincipal, groups);
            } catch (ParseException e) {
                if (e.getCause() instanceof UnresolvableKeyException) {
                    MechanismLogging.log.noUsableKey();
                    return reportInternalError(httpMessageContext);
                } else {
                    MechanismLogging.log.unableToValidateBearerToken(e);
                    return httpMessageContext.responseUnauthorized();
                }
            } catch (Exception e) {
                MechanismLogging.log.unableToValidateBearerToken(e);
                return reportInternalError(httpMessageContext);
            }
        } else {
            MechanismLogging.log.noUsableBearerTokenFound();
            return httpMessageContext.isProtected() ? httpMessageContext.responseUnauthorized()
                    : httpMessageContext.doNothing();
        }
    }

    private AuthenticationStatus reportInternalError(HttpMessageContext httpMessageContext) {
        try {
            httpMessageContext.getResponse().sendError(500);
        } catch (IOException ioException) {
            throw new IllegalStateException(ioException);
        }
        return AuthenticationStatus.SEND_FAILURE;
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