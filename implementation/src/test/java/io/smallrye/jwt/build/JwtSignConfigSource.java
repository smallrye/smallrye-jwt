package io.smallrye.jwt.build;

import java.util.Collections;
import java.util.Map;

import org.eclipse.microprofile.config.spi.ConfigSource;

public class JwtSignConfigSource implements ConfigSource {

    @Override
    public Map<String, String> getProperties() {
        return Collections.singletonMap("smallrye.jwt.sign.private-key-location", "/privateKey.pem");
    }

    @Override
    public String getValue(String propertyName) {
        return getProperties().get(propertyName);
    }

    @Override
    public String getName() {
        return "test-source";
    }
}
