package io.smallrye.jwt.config;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.inject.Provider;

import org.jboss.weld.junit4.WeldInitiator;
import org.junit.Rule;

import io.smallrye.config.inject.ConfigExtension;

public class JWTAuthContextInfoProviderTest {
    @Rule
    public WeldInitiator weld = WeldInitiator.from(JWTAuthContextInfoProvider.class, ConfigExtension.class)
            .addBeans()
            .activate(RequestScoped.class, ApplicationScoped.class)
            .inject(this)
            .build();

    @Inject
    Provider<JWTAuthContextInfoProvider> context;

}
