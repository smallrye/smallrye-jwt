package io.smallrye.jwt.tck;

import org.jboss.arquillian.container.test.spi.client.deployment.ApplicationArchiveProcessor;
import org.jboss.arquillian.core.spi.LoadableExtension;

public class SmallRyeJWTExtension implements LoadableExtension {
    @Override
    public void register(final ExtensionBuilder builder) {
        builder.service(ApplicationArchiveProcessor.class, SmallRyeJWTArchiveProcessor.class);
    }
}
