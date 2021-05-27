package io.smallrye.jwt.build;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.eclipse.microprofile.config.spi.ConfigSource;

import io.smallrye.jwt.build.impl.JwtBuildUtils;

public class JwtBuildConfigSource implements ConfigSource {

    private static final Set<String> PROPERTY_NAMES = new HashSet<>(Arrays.asList(JwtBuildUtils.SIGN_KEY_LOCATION_PROPERTY,
            JwtBuildUtils.ENC_KEY_LOCATION_PROPERTY,
            JwtBuildUtils.SIGN_KEY_ID_PROPERTY,
            JwtBuildUtils.ENC_KEY_ID_PROPERTY,
            JwtBuildUtils.NEW_TOKEN_ISSUER_PROPERTY,
            JwtBuildUtils.NEW_TOKEN_AUDIENCE_PROPERTY,
            JwtBuildUtils.NEW_TOKEN_LIFESPAN_PROPERTY,
            JwtBuildUtils.NEW_TOKEN_OVERRIDE_CLAIMS_PROPERTY));

    boolean overrideMatchingClaims;
    boolean lifespanPropertyRequired;
    boolean issuerPropertyRequired;
    boolean audiencePropertyRequired;
    int signingKeyCallCount;
    String encryptionKeyLocation = "/publicKey.pem";
    String signingKeyLocation = "/privateKey.pem";

    private String signingKeyId;
    private String encryptionKeyId;

    @Override
    public Map<String, String> getProperties() {
        Map<String, String> map = new HashMap<>();
        map.put(JwtBuildUtils.SIGN_KEY_LOCATION_PROPERTY, signingKeyLocation);

        if (encryptionKeyId != null) {
            map.put(JwtBuildUtils.ENC_KEY_ID_PROPERTY, encryptionKeyId);
        }
        if (signingKeyId != null) {
            map.put(JwtBuildUtils.SIGN_KEY_ID_PROPERTY, signingKeyId);
        }
        map.put(JwtBuildUtils.ENC_KEY_LOCATION_PROPERTY, encryptionKeyLocation);
        if (lifespanPropertyRequired) {
            map.put(JwtBuildUtils.NEW_TOKEN_LIFESPAN_PROPERTY, "2000");
        }
        if (issuerPropertyRequired) {
            map.put(JwtBuildUtils.NEW_TOKEN_ISSUER_PROPERTY, "https://custom-issuer");
        }
        if (audiencePropertyRequired) {
            map.put(JwtBuildUtils.NEW_TOKEN_AUDIENCE_PROPERTY, "https://custom-audience");
        }

        map.put(JwtBuildUtils.NEW_TOKEN_OVERRIDE_CLAIMS_PROPERTY, String.valueOf(overrideMatchingClaims));
        return map;
    }

    @Override
    public String getValue(String propertyName) {
        if (JwtBuildUtils.SIGN_KEY_LOCATION_PROPERTY.equals(propertyName)) {
            signingKeyCallCount++;
        }
        return getProperties().get(propertyName);
    }

    @Override
    public String getName() {
        return "test-source";
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

    @Override
    public Set<String> getPropertyNames() {
        return PROPERTY_NAMES;
    }

    public void setOverrideMatchingClaims(boolean override) {
        overrideMatchingClaims = override;
    }

    public void resetSigningKeyCallCount() {
        signingKeyCallCount = 0;
    }

    public Object getSigningKeyCallCount() {
        return signingKeyCallCount;
    }

    public void setSigningKeyId(String signingKeyId) {
        this.signingKeyId = signingKeyId;
    }

    public void setEncryptonKeyId(String encryptionKeyId) {
        this.encryptionKeyId = encryptionKeyId;
    }

}
