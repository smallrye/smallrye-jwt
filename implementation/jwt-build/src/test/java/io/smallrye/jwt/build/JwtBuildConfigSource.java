package io.smallrye.jwt.build;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.eclipse.microprofile.config.spi.ConfigSource;

public class JwtBuildConfigSource implements ConfigSource {
    private static final String SIGN_KEY_LOCATION_PROPERTY = "smallrye.jwt.sign.key.location";
    private static final String DEPRECATED_SIGN_KEY_LOCATION_PROPERTY = "smallrye.jwt.sign.key-location";
    private static final String ENC_KEY_LOCATION_PROPERTY = "smallrye.jwt.encrypt.key.location";
    private static final String DEPRECATED_ENC_KEY_LOCATION_PROPERTY = "smallrye.jwt.encrypt.key-location";

    boolean signingKeyAvailable = true;
    boolean lifespanPropertyRequired;
    boolean issuerPropertyRequired;
    boolean audiencePropertyRequired;
    String encryptionKeyLocation = "/publicKey.pem";
    String signingKeyLocation = "/privateKey.pem";
    String signingKeyLocProperty = SIGN_KEY_LOCATION_PROPERTY;
    String encryptionKeyLocProperty = ENC_KEY_LOCATION_PROPERTY;

    @Override
    public Map<String, String> getProperties() {
        Map<String, String> map = new HashMap<>();
        if (signingKeyAvailable) {
            map.put(signingKeyLocProperty, signingKeyLocation);
        }
        map.put(encryptionKeyLocProperty, encryptionKeyLocation);
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

    public void enableDeprecatedSigningKeyProperty(boolean enable) {
        this.signingKeyLocProperty = enable ? DEPRECATED_SIGN_KEY_LOCATION_PROPERTY : SIGN_KEY_LOCATION_PROPERTY;
    }

    public void enableDeprecatedEncryptionKeyProperty(boolean enable) {
        this.encryptionKeyLocProperty = enable ? DEPRECATED_ENC_KEY_LOCATION_PROPERTY : ENC_KEY_LOCATION_PROPERTY;
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

    @Override
    public Set<String> getPropertyNames() {
        return new HashSet<>(Arrays.asList("smallrye.jwt.sign.key-location",
                "smallrye.jwt.encrypt.key-location",
                "smallrye.jwt.new-token.lifespan",
                "smallrye.jwt.new-token.issuer",
                "smallrye.jwt.new-token.audience"));
    }
}
