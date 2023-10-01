package io.smallrye.jwt.auth.principal;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class AwsAlbKeyConfigurationValidatorTest {

    @Test
    void containsSubPath() {
        assertTrue(AwsAlbKeyConfigurationValidator
                .containsSubPath("https://public-keys.auth.elb.eu-central-1.amazonaws.com/keyid"));
        assertTrue(AwsAlbKeyConfigurationValidator
                .containsSubPath("https://public-keys.auth.elb.eu-central-1.amazonaws.com/index/keyid"));
        assertTrue(AwsAlbKeyConfigurationValidator
                .containsSubPath("https://public-keys.auth.elb.eu-central-1.amazonaws.com/index.html"));
        assertFalse(
                AwsAlbKeyConfigurationValidator.containsSubPath("https://public-keys.auth.elb.eu-central-1.amazonaws.com/"));
        assertFalse(AwsAlbKeyConfigurationValidator.containsSubPath("https://public-keys.auth.elb.eu-central-1.amazonaws.com"));
    }

    @Test
    void removeEndingSlash() {
        assertTrue(AwsAlbKeyConfigurationValidator.removeEndingSlash("key-location/keyid")
                .equals("key-location/keyid"));
        assertTrue(AwsAlbKeyConfigurationValidator.removeEndingSlash("key-location/index/keyid/")
                .equals("key-location/index/keyid"));
        assertTrue(AwsAlbKeyConfigurationValidator.removeEndingSlash("key-location/index.html/")
                .equals("key-location/index.html"));
        assertTrue(AwsAlbKeyConfigurationValidator.removeEndingSlash("key-location/")
                .equals("key-location"));
        assertTrue(AwsAlbKeyConfigurationValidator.removeEndingSlash("key-location")
                .equals("key-location"));
    }
}
