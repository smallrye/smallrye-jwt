package io.smallrye.jwt.build;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.eclipse.microprofile.config.spi.ConfigSource;

import io.smallrye.jwt.build.impl.JwtBuildUtils;
import io.smallrye.jwt.util.KeyUtils;

public class JwtBuildConfigSource implements ConfigSource {

    private static final Set<String> PROPERTY_NAMES = new HashSet<>(Arrays.asList(
            JwtBuildUtils.SIGN_KEY_ID_PROPERTY,
            JwtBuildUtils.SIGN_KEY_RELAX_VALIDATION_PROPERTY,
            JwtBuildUtils.ENC_KEY_RELAX_VALIDATION_PROPERTY,
            JwtBuildUtils.ENC_KEY_ID_PROPERTY,
            JwtBuildUtils.NEW_TOKEN_ISSUER_PROPERTY,
            JwtBuildUtils.NEW_TOKEN_AUDIENCE_PROPERTY,
            JwtBuildUtils.NEW_TOKEN_LIFESPAN_PROPERTY,
            JwtBuildUtils.NEW_TOKEN_OVERRIDE_CLAIMS_PROPERTY,
            JwtBuildUtils.NEW_TOKEN_ADD_DEFAULT_CLAIMS_PROPERTY,
            JwtBuildUtils.NEW_TOKEN_SIGNATURE_ALG_PROPERTY,
            JwtBuildUtils.NEW_TOKEN_KEY_ENCRYPTION_ALG_PROPERTY,
            JwtBuildUtils.SIGN_KEYSTORE_KEY_ALIAS,
            JwtBuildUtils.ENC_KEYSTORE_KEY_ALIAS));

    boolean overrideMatchingClaims;
    boolean lifespanPropertyRequired;
    boolean issuerPropertyRequired;
    boolean audiencePropertyRequired;
    int signingKeyCallCount;
    String encryptionKeyLocation = "/publicKey.pem";
    String signingKeyLocation = "/privateKey.pem";

    private String signingKeyId;
    private String encryptionKeyId;

    private String signatureAlg;

    private String keyEncryptionAlg;
    private String contentEncryptionAlg;

    private boolean useKeyStore;
    private boolean useSignKeyProperty;
    private boolean useEncryptionKeyProperty;

    private boolean relaxSignatureKeyValidation;
    private boolean relaxEncryptionKeyValidation;
    private boolean addDefaultClaims = true;

    @Override
    public Map<String, String> getProperties() {
        Map<String, String> map = new HashMap<>();
        if (useKeyStore) {
            map.put(JwtBuildUtils.KEYSTORE_PASSWORD, "password");
        }

        if (!useSignKeyProperty) {
            map.put(JwtBuildUtils.SIGN_KEY_LOCATION_PROPERTY, signingKeyLocation);
            if (useKeyStore) {
                map.put(JwtBuildUtils.SIGN_KEYSTORE_KEY_ALIAS, "server");
            }
        } else {
            try {
                map.put(JwtBuildUtils.SIGN_KEY_PROPERTY, KeyUtils.readKeyContent(signingKeyLocation));
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        }
        if (!useEncryptionKeyProperty) {
            map.put(JwtBuildUtils.ENC_KEY_LOCATION_PROPERTY, encryptionKeyLocation);
            if (useKeyStore) {
                map.put(JwtBuildUtils.ENC_KEYSTORE_KEY_ALIAS, "server");
            }
        } else {
            try {
                map.put(JwtBuildUtils.ENC_KEY_PROPERTY, KeyUtils.readKeyContent(encryptionKeyLocation));
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        }

        if (signatureAlg != null) {
            map.put(JwtBuildUtils.NEW_TOKEN_SIGNATURE_ALG_PROPERTY, signatureAlg);
        }
        if (keyEncryptionAlg != null) {
            map.put(JwtBuildUtils.NEW_TOKEN_KEY_ENCRYPTION_ALG_PROPERTY, keyEncryptionAlg);
        }
        if (contentEncryptionAlg != null) {
            map.put(JwtBuildUtils.NEW_TOKEN_CONTENT_ENCRYPTION_ALG_PROPERTY, contentEncryptionAlg);
        }
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

        if (relaxSignatureKeyValidation) {
            map.put(JwtBuildUtils.SIGN_KEY_RELAX_VALIDATION_PROPERTY, String.valueOf(relaxSignatureKeyValidation));
        }

        if (relaxEncryptionKeyValidation) {
            map.put(JwtBuildUtils.ENC_KEY_RELAX_VALIDATION_PROPERTY, String.valueOf(relaxEncryptionKeyValidation));
        }

        map.put(JwtBuildUtils.NEW_TOKEN_ADD_DEFAULT_CLAIMS_PROPERTY, String.valueOf(addDefaultClaims));

        map.put(JwtBuildUtils.NEW_TOKEN_OVERRIDE_CLAIMS_PROPERTY, String.valueOf(overrideMatchingClaims));
        return map;
    }

    @Override
    public String getValue(String propertyName) {
        if (JwtBuildUtils.SIGN_KEY_LOCATION_PROPERTY.equals(propertyName) && !useSignKeyProperty
                || JwtBuildUtils.SIGN_KEY_PROPERTY.equals(propertyName) && useSignKeyProperty) {
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
        Set<String> names = new HashSet<>(PROPERTY_NAMES);
        if (useSignKeyProperty) {
            names.add(JwtBuildUtils.SIGN_KEY_PROPERTY);
        } else {
            names.add(JwtBuildUtils.SIGN_KEY_LOCATION_PROPERTY);
        }
        if (useEncryptionKeyProperty) {
            names.add(JwtBuildUtils.ENC_KEY_PROPERTY);
        } else {
            names.add(JwtBuildUtils.ENC_KEY_LOCATION_PROPERTY);
        }
        if (useKeyStore) {
            names.add(JwtBuildUtils.KEYSTORE_PASSWORD);
            names.add(JwtBuildUtils.SIGN_KEYSTORE_KEY_ALIAS);
            names.add(JwtBuildUtils.ENC_KEYSTORE_KEY_ALIAS);
        }
        return names;
    }

    public void setOverrideMatchingClaims(boolean override) {
        overrideMatchingClaims = override;
    }

    public void setAddDefaultClaims(boolean add) {
        addDefaultClaims = add;
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

    public void setSignatureAlgorithm(String alg) {
        this.signatureAlg = alg;
    }

    public void setKeyEncryptionAlgorithm(String alg) {
        this.keyEncryptionAlg = alg;
    }

    public void setContentEncryptionAlgorithm(String alg) {
        this.contentEncryptionAlg = alg;
    }

    public void setUseSignKeyProperty(boolean useSignKeyProperty) {
        this.useSignKeyProperty = useSignKeyProperty;
    }

    public void setUseKeyStore(boolean useKeyStore) {
        this.useKeyStore = useKeyStore;
    }

    public void setUseEncryptionKeyProperty(boolean useEncryptionKeyProperty) {
        this.useEncryptionKeyProperty = useEncryptionKeyProperty;
    }

    public void setRelaxSignatureKeyValidation(boolean relax) {
        this.relaxSignatureKeyValidation = relax;

    }

    public void setRelaxEncryptionKeyValidation(boolean relax) {
        this.relaxEncryptionKeyValidation = relax;
    }

}
