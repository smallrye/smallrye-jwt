package io.smallrye.jwt.tck;

import java.io.File;

import javax.enterprise.inject.spi.Extension;
import javax.ws.rs.ext.Providers;

import org.jboss.arquillian.container.test.spi.client.deployment.ApplicationArchiveProcessor;
import org.jboss.arquillian.test.spi.TestClass;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;

import io.smallrye.jwt.auth.jaxrs.JWTAuthenticationFilter;

public class SmallRyeJWTArchiveProcessor implements ApplicationArchiveProcessor {
    @Override
    public void process(Archive<?> applicationArchive, TestClass testClass) {
        if (applicationArchive instanceof WebArchive) {
            WebArchive war = (WebArchive) applicationArchive;
            war.addClass(OptionalAwareSmallRyeJWTAuthCDIExtension.class);
            war.addAsServiceProvider(Extension.class, OptionalAwareSmallRyeJWTAuthCDIExtension.class);
            war.addAsServiceProvider(Providers.class, JWTAuthenticationFilter.class);

            if (!war.contains("META-INF/microprofile-config.properties")) {
                war.addAsManifestResource("microprofile-config-local.properties", "microprofile-config.properties");
            }

            String[] deps = {
                    "io.smallrye:smallrye-jwt",
                    "io.smallrye.config:smallrye-config",
                    "org.jboss.resteasy:resteasy-servlet-initializer",
                    "org.jboss.resteasy:resteasy-jaxrs",
                    "org.jboss.resteasy:resteasy-client",
                    "org.jboss.resteasy:resteasy-cdi",
                    "org.jboss.resteasy:resteasy-json-binding-provider",
                    "org.jboss.weld.servlet:weld-servlet-core"
            };
            File[] dependencies = Maven.resolver()
                    .loadPomFromFile(new File("pom.xml"))
                    .resolve(deps)
                    .withTransitivity()
                    .asFile();

            war.addAsLibraries(dependencies);
        }
    }
}
