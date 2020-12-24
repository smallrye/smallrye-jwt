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
 *
 */
package io.smallrye.jwt.auth.cdi;

import javax.enterprise.event.Observes;
import javax.enterprise.inject.Instance;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.BeforeBeanDiscovery;
import javax.enterprise.inject.spi.CDI;
import javax.enterprise.inject.spi.Extension;

import io.smallrye.jwt.auth.mechanism.JWTHttpAuthenticationMechanism;
import io.smallrye.jwt.auth.principal.DefaultJWTParser;
import io.smallrye.jwt.config.JWTAuthContextInfoProvider;

/**
 * Extension to support JWT producers as well as the internal
 * components of SmallRye JWT in a CDI environment. Applications wishing
 * to use MP-JWT with SmallRye should enable this extension by adding
 * a file named META-INF/services/javax.enterprise.inject.spi.Extension
 * to their project with a line giving the fully qualified class name of
 * this class.
 *
 * Note, this extension is not enabled by default.
 *
 *
 * @author Michael Edgar {@literal <michael@xlate.io>}
 */
public class SmallRyeJWTAuthCDIExtension implements Extension {

    private static final String HTTP_AUTH_MECHANISM_CLASS_NAME = "javax.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism";
    private static final String JWT_AUTHENTICATION_FILTER_CLASS_NAME = "io.smallrye.jwt.auth.jaxrs.JWTAuthenticationFilter";

    public static boolean isHttpAuthMechanismEnabled() {
        boolean enabled = false;

        if (isEESecurityAvailable()) {
            Instance<JWTHttpAuthenticationMechanism> instance;

            try {
                instance = CDI.current().select(JWTHttpAuthenticationMechanism.class);
                enabled = instance.isResolvable();
            } catch (@SuppressWarnings("unused") Exception e) {
                //Ignore exceptions, consider HTTP authentication mechanism to be disabled
            }
        }

        return enabled;
    }

    private static boolean isEESecurityAvailable() {
        try {
            Class.forName(HTTP_AUTH_MECHANISM_CLASS_NAME);
            return true;
        } catch (@SuppressWarnings("unused") ClassNotFoundException e) {
            return false;
        }
    }

    private static boolean isJaxrsAuthenticationFilterAvailable() {
        try {
            Class.forName(JWT_AUTHENTICATION_FILTER_CLASS_NAME);
            return true;
        } catch (@SuppressWarnings("unused") ClassNotFoundException e) {
            return false;
        }
    }

    private static Class<?> loadJaxrsAuthenticationFilter() {
        try {
            return Class.forName(JWT_AUTHENTICATION_FILTER_CLASS_NAME);
        } catch (@SuppressWarnings("unused") ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    protected boolean registerOptionalClaimTypeProducer() {
        return false;
    }

    void beforeBeanDiscovery(@Observes BeforeBeanDiscovery event, BeanManager beanManager) {
        CDILogging.log.beforeBeanDiscovery(beanManager);

        // TODO: Do not add CDI beans unless @LoginConfig (or other trigger) is configured
        addAnnotatedType(event, beanManager, ClaimValueProducer.class);
        addAnnotatedType(event, beanManager, CommonJwtProducer.class);
        addAnnotatedType(event, beanManager, DefaultJWTParser.class);
        addAnnotatedType(event, beanManager, JWTCallerPrincipalFactoryProducer.class);
        addAnnotatedType(event, beanManager, JsonValueProducer.class);
        addAnnotatedType(event, beanManager, JWTAuthContextInfoProvider.class);
        addAnnotatedType(event, beanManager, PrincipalProducer.class);
        addAnnotatedType(event, beanManager, RawClaimTypeProducer.class);
        if (registerOptionalClaimTypeProducer()) {
            addAnnotatedType(event, beanManager, OptionalClaimTypeProducer.class);
        }

        if (isEESecurityAvailable()) {
            addAnnotatedType(event, beanManager, JWTHttpAuthenticationMechanism.class);
            CDILogging.log.jwtHttpAuthenticationMechanismRegistered();
        } else if (isJaxrsAuthenticationFilterAvailable()) {
            // EE Security is not available, register the JAX-RS authentication filter.
            addAnnotatedType(event, beanManager, loadJaxrsAuthenticationFilter());
            CDILogging.log.jwtHttpAuthenticationMechanismNotRegistered();
        }
    }

    void addAnnotatedType(BeforeBeanDiscovery event, BeanManager beanManager, Class<?> type) {
        final String id = "SmallRye" + type.getSimpleName();
        event.addAnnotatedType(beanManager.createAnnotatedType(type), id);
        CDILogging.log.addedType(type.getName());
    }
}
