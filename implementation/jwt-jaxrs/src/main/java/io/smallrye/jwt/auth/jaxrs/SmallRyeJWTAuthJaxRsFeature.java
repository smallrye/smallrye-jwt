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
package io.smallrye.jwt.auth.jaxrs;

import jakarta.ws.rs.core.Application;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Feature;
import jakarta.ws.rs.core.FeatureContext;

import org.eclipse.microprofile.auth.LoginConfig;

/**
 * JAX-RS Feature to support JWT authentication and authorization filters, This feature must
 * be enabled by client applications by using the
 * {@link Application#getClasses()} method or via another feature.
 *
 * @author Michael Edgar {@literal <michael@xlate.io>}
 */
public class SmallRyeJWTAuthJaxRsFeature implements Feature {

    @Context
    private Application restApplication;

    @Override
    public boolean configure(FeatureContext context) {
        boolean enabled = mpJwtEnabled();

        if (enabled) {
            context.register(JWTAuthorizationFilterRegistrar.class);

            context.register(JWTAuthenticationFilter.class);

            JAXRSLogging.log.mpJWTLoginConfigPresent(getClass().getSimpleName());
        } else {
            JAXRSLogging.log.mpJWTLoginConfigNotFound(getClass().getSimpleName());
        }

        return enabled;
    }

    boolean mpJwtEnabled() {
        boolean enabled = false;

        if (restApplication != null) {
            Class<?> applicationClass = restApplication.getClass();

            if (applicationClass.isAnnotationPresent(LoginConfig.class)) {
                LoginConfig config = applicationClass.getAnnotation(LoginConfig.class);
                enabled = "MP-JWT".equals(config.authMethod());
            }
        }

        return enabled;
    }
}
