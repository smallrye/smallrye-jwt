package io.smallrye.jwt.build;

import java.util.HashMap;
import java.util.Map;

import org.eclipse.microprofile.config.spi.ConfigSource;

public class JwtBuildConfigSource implements ConfigSource {

    boolean signingKeyAvailable = true;
    String encryptionKeyLocation = "/publicKey.pem";
    String signingKeyLocation = "/privateKey.pem";

    @Override
    public Map<String, String> getProperties() {
        Map<String, String> map = new HashMap<>();
        if (signingKeyAvailable) {
            map.put("smallrye.jwt.sign.key-location", signingKeyLocation);
        }
        map.put("smallrye.jwt.encrypt.key-location", encryptionKeyLocation);
        return map;
    }

    @Override
    public String getValue(String propertyName) {
        return getProperties().get(propertyName);
    }

    @Override
    public String getName() {
        return "test-source";
    }

    public void setSigningKeyAvailability(boolean available) {
        signingKeyAvailable = available;
    }

    public void setEncryptionKeyLocation(String location) {
        this.encryptionKeyLocation = location;
    }

    public void setSigningKeyLocation(String location) {
        this.signingKeyLocation = location;
    }
}
