/**
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
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.BeforeBeanDiscovery;
import javax.enterprise.inject.spi.Extension;

import org.jboss.logging.Logger;

import io.smallrye.jwt.auth.jaxrs.JWTAuthFilter;
import io.smallrye.jwt.auth.mechanism.JWTHttpAuthenticationMechanism;
import io.smallrye.jwt.config.JWTAuthContextInfoProvider;

public class SmallRyeJWTAuthCDIExtension implements Extension {

    private static Logger logger = Logger.getLogger(SmallRyeJWTAuthCDIExtension.class);

    void beforeBeanDiscovery(@Observes BeforeBeanDiscovery event, BeanManager beanManager) {
        logger.debugf("beanManager = %s", beanManager);

        // TODO: Do not add CDI beans unless @LoginConfig (or other trigger) is configured
        addAnnotatedType(event, beanManager, ClaimValueProducer.class);
        addAnnotatedType(event, beanManager, CommonJwtProducer.class);
        addAnnotatedType(event, beanManager, JsonValueProducer.class);
        addAnnotatedType(event, beanManager, JWTAuthContextInfoProvider.class);
        addAnnotatedType(event, beanManager, JWTAuthFilter.class);
        addAnnotatedType(event, beanManager, PrincipalProducer.class);
        addAnnotatedType(event, beanManager, RawClaimTypeProducer.class);

        try {
            Class.forName("javax.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism");
            addAnnotatedType(event, beanManager, JWTHttpAuthenticationMechanism.class);
            logger.debugf("EE Security is available, JWTHttpAuthenticationMechanism has been registered");
        } catch (@SuppressWarnings("unused") ClassNotFoundException e) {
            // EE Security is not available, register the JAX-RS authentication filter.
            logger.infof("EE Security is not available, JWTHttpAuthenticationMechanism will not be registered");
        }
    }

    void addAnnotatedType(BeforeBeanDiscovery event, BeanManager beanManager, Class<?> type) {
        final String id = "SmallRye" + type.getSimpleName();
        event.addAnnotatedType(beanManager.createAnnotatedType(type), id);
        logger.debugf("Added type: %s", type.getName());
    }
}
