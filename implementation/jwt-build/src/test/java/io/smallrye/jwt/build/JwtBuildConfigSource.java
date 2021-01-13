package io.smallrye.jwt.build;

import java.util.HashMap;
import java.util.Map;

import org.eclipse.microprofile.config.spi.ConfigSource;

public class JwtBuildConfigSource implements ConfigSource {

    boolean signingKeyAvailable = true;
    boolean lifespanPropertyRequired;
    boolean issuerPropertyRequired;
    boolean audiencePropertyRequired;
    String encryptionKeyLocation = "/publicKey.pem";
    String signingKeyLocation = "/privateKey.pem";

    @Override
    public Map<String, String> getProperties() {
        Map<String, String> map = new HashMap<>();
        if (signingKeyAvailable) {
            map.put("smallrye.jwt.sign.key-location", signingKeyLocation);
        }
        map.put("smallrye.jwt.encrypt.key-location", encryptionKeyLocation);
        if (lifespanPropertyRequired) {
            map.put("smallrye.jwt.new-token.lifespan", "2000");
        }
        if (issuerPropertyRequired) {
            map.put("smallrye.jwt.new-token.issuer", "https://custom-issuer");
        }
        if (audiencePropertyRequired) {
            map.put("smallrye.jwt.new-token.audience", "https://custom-audience");
        }
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

    void setLifespanPropertyRequired(boolean lifespanPropertyRequired) {
        this.lifespanPropertyRequired = lifespanPropertyRequired;
    }

    public void setIssuerPropertyRequired(boolean issuerPropertyRequired) {
        this.issuerPropertyRequired = issuerPropertyRequired;
    }

    public void setAudiencePropertyRequired(boolean audiencePropertyRequired) {
        this.audiencePropertyRequired = audiencePropertyRequired;
    }
}
