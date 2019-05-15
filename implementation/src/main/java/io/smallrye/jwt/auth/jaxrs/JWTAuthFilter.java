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
import java.lang.reflect.Method;
import java.security.Principal;
import java.util.Arrays;
import java.util.Set;

import javax.annotation.Priority;
import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.logging.Logger;

import io.smallrye.jwt.auth.cdi.PrincipalProducer;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipal;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipalFactory;
import io.smallrye.jwt.auth.principal.ParseException;


/**
 * A JAX-RS ContainerRequestFilter prototype
 * TODO - JavaDoc and tests
 */
@Priority(Priorities.AUTHENTICATION)
public class JWTAuthFilter implements ContainerRequestFilter {

    private static Logger logger = Logger.getLogger(JWTAuthFilter.class);

    @Context
    private ResourceInfo resourceInfo;

    @Inject
    private JWTAuthContextInfo authContextInfo;

    @Inject
    private PrincipalProducer producer;

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        JsonWebToken jwtPrincipal = getJsonWebToken(requestContext);

        if (!isPermitted(resourceInfo, jwtPrincipal)) {
            // TODO: throw NotAuthorizedException to allow client to handle?
            requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
        }
    }

    JsonWebToken getJsonWebToken(ContainerRequestContext requestContext) {
        final SecurityContext securityContext = requestContext.getSecurityContext();
        final Principal principal = securityContext.getUserPrincipal();
        JsonWebToken jwtPrincipal = null;

        if (principal instanceof JsonWebToken) {
            jwtPrincipal = (JsonWebToken) principal;
        } else {
            String bearerToken = getBearerToken(requestContext);

            if (bearerToken != null) {
                try {
                    jwtPrincipal = validate(bearerToken);
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

        return jwtPrincipal;
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
    //TODO: consolidate with common logic found in JWTHttpAuthenticationMechanism#getBearerToken if possible
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

    /**
     * MP-JWT Specification 1.1.1, Section 7.3
     *
     * Determine if access to the currently requested resource is permitted to
     * principal.
     *
     * @param resourceInfo
     * @param principal
     */
    boolean isPermitted(ResourceInfo resourceInfo, JsonWebToken principal) {
        Class<?> resourceClass = resourceInfo.getResourceClass();
        Method resourceMethod = resourceInfo.getResourceMethod();
        boolean permitted;

        // TODO: Check for EJB annotations and defer check to EJB container in that case?

        if (resourceMethod.isAnnotationPresent(PermitAll.class)) {
            permitted = true;
        } else if (resourceMethod.isAnnotationPresent(DenyAll.class)) {
            permitted = false;
        } else if (resourceMethod.isAnnotationPresent(RolesAllowed.class)) {
            permitted = groupsAllowed(resourceMethod.getAnnotation(RolesAllowed.class), principal);
        } else if (resourceClass.isAnnotationPresent(PermitAll.class)) {
            permitted = true;
        } else if (resourceClass.isAnnotationPresent(DenyAll.class)) {
            permitted = false;
        } else if (resourceClass.isAnnotationPresent(RolesAllowed.class)) {
            permitted = groupsAllowed(resourceClass.getAnnotation(RolesAllowed.class), principal);
        } else {
            permitted = true;
        }

        return permitted;
    }

    boolean groupsAllowed(RolesAllowed annotation, JsonWebToken principal) {
        boolean allowed;

        if (principal != null) {
            final Set<String> groups = principal.getGroups();

            allowed = Arrays.stream(annotation.value())
                            .filter(role -> groups.contains(role))
                            .map(role -> Boolean.TRUE)
                            .findFirst()
                            .orElse(Boolean.FALSE);
        } else {
            allowed = false;
        }

        return allowed;
    }
}