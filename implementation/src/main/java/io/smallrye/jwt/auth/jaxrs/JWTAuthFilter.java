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
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.ext.Provider;
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
    @Inject
    private JWTAuthContextInfo authContextInfo;

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        String authHeaderVal = requestContext.getHeaderString("Authorization");
        System.err.printf("JWTAuthFilter.authHeaderVal: %s\n", authHeaderVal);
        if (authHeaderVal.startsWith("Bearer")) {
            try {
                String bearerToken = authHeaderVal.substring(7);
                JWTCallerPrincipal jwtPrincipal = validate(bearerToken);
                // Install the JWT principal as the caller
                final SecurityContext securityContext = requestContext.getSecurityContext();
                JWTSecurityContext jwtSecurityContext = new JWTSecurityContext(securityContext, jwtPrincipal);
                requestContext.setSecurityContext(jwtSecurityContext);
                System.out.printf("Success\n");
            }
            catch (Exception ex) {
                System.err.printf("Failed with ex=%s\n", ex.getMessage());
                ex.printStackTrace();
                requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
            }
        }
        else {
            System.err.printf("Failed due to missing Authorization bearer token\n");
            requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
        }
    }

    protected JWTCallerPrincipal validate(String bearerToken) throws ParseException {
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JWTCallerPrincipal callerPrincipal = factory.parse(bearerToken, authContextInfo);
        return callerPrincipal;
    }
}