package io.smallrye.jwt.tck;

import java.io.File;

import org.jboss.arquillian.container.test.spi.client.deployment.ApplicationArchiveProcessor;
import org.jboss.arquillian.test.spi.TestClass;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;

public class SmallRyeJWTArchiveProcessor implements ApplicationArchiveProcessor {
    @Override
    public void process(Archive<?> applicationArchive, TestClass testClass) {
        if (applicationArchive instanceof WebArchive) {
            WebArchive war = (WebArchive) applicationArchive;

            String[] deps = {
                    "io.smallrye:smallrye-jwt",
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
            System.out.println(war.toString(true));
        }
    }
}
