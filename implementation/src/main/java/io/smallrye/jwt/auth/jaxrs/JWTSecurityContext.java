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

import java.security.Principal;

import javax.ws.rs.core.SecurityContext;

import io.smallrye.jwt.auth.principal.JWTCallerPrincipal;

/**
 * A delegating JAX-RS SecurityContext prototype that provides access to the JWTCallerPrincipal
 * TODO
 */
public class JWTSecurityContext implements SecurityContext {
    private SecurityContext delegate;
    private JWTCallerPrincipal principal;

    JWTSecurityContext(SecurityContext delegate, JWTCallerPrincipal principal) {
        this.delegate = delegate;
        this.principal = principal;
    }
    @Override
    public Principal getUserPrincipal() {
        return principal;
    }

    @Override
    public boolean isUserInRole(String role) {
        return principal.getGroups().contains(role);
    }

    @Override
    public boolean isSecure() {
        return delegate.isSecure();
    }

    @Override
    public String getAuthenticationScheme() {
        return delegate.getAuthenticationScheme();
    }
}