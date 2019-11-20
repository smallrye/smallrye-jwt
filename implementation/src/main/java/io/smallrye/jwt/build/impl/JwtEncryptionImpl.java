package io.smallrye.jwt.build.impl;

import java.security.Key;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;

import javax.crypto.SecretKey;

import org.eclipse.microprofile.config.ConfigProvider;
import org.jose4j.jwe.JsonWebEncryption;

import io.smallrye.jwt.KeyUtils;
import io.smallrye.jwt.algorithm.ContentEncryptionAlgorithm;
import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.jwt.build.JwtEncryptionBuilder;
import io.smallrye.jwt.build.JwtEncryptionException;
import io.smallrye.jwt.build.JwtSignatureException;

/**
 * Default JWT Encryption implementation
 */
class JwtEncryptionImpl implements JwtEncryptionBuilder {
    boolean innerSigned;
    String claims;
    Map<String, Object> headers = new HashMap<>();

    JwtEncryptionImpl(String claims) {
        this.claims = claims;
    }

    JwtEncryptionImpl(String claims, boolean innerSigned) {
        this.claims = claims;
        this.innerSigned = innerSigned;
    }

    @Override
    public String encrypt(PublicKey keyEncryptionKey) throws JwtEncryptionException {
        return encryptInternal(keyEncryptionKey);
    }

    @Override
    public String encrypt(SecretKey keyEncryptionKey) throws JwtEncryptionException {
        return encryptInternal(keyEncryptionKey);
    }

    @Override
    public String encrypt() throws JwtSignatureException {
        return encryptInternal(getKeyEncryptionKeyFromConfig((String) headers.get("kid")));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtEncryptionBuilder header(String name, Object value) {
        if ("alg".equals(name)) {
            return keyEncryptionAlgorithm(toKeyEncryptionAlgorithm((String) value));
        } else if ("enc".equals(name)) {
            return contentEncryptionAlgorithm(toContentEncryptionAlgorithm((String) value));
        } else {
            headers.put(name, value);
            return this;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtEncryptionBuilder keyEncryptionAlgorithm(KeyEncryptionAlgorithm algorithm) {
        headers.put("alg", algorithm.getAlgorithm());
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtEncryptionBuilder contentEncryptionAlgorithm(ContentEncryptionAlgorithm algorithm) {
        headers.put("enc", algorithm.getAlgorithm());
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtEncryptionBuilder keyEncryptionKeyId(String keyId) {
        headers.put("kid", keyId);
        return this;
    }

    private String encryptInternal(Key key) {
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setPlaintext(claims);
        for (Map.Entry<String, Object> entry : headers.entrySet()) {
            jwe.getHeaders().setObjectHeaderValue(entry.getKey(), entry.getValue());
        }
        if (innerSigned && !headers.containsKey("cty")) {
            jwe.getHeaders().setObjectHeaderValue("cty", "JWT");
        }
        jwe.setAlgorithmHeaderValue(getKeyEncryptionAlgorithm(key));
        jwe.setEncryptionMethodHeaderParameter(getContentEncryptionAlgorithm());
        jwe.setKey(key);
        try {
            return jwe.getCompactSerialization();
        } catch (org.jose4j.lang.JoseException ex) {
            throw new JwtEncryptionException(ex.getMessage(), ex);
        }
    }

    private String getKeyEncryptionAlgorithm(Key keyEncryptionKey) {
        String alg = (String) headers.get("alg");
        if ("dir".equals(alg)) {
            throw new JwtEncryptionException("Direct content encryption is currently not supported");
        }
        if (keyEncryptionKey instanceof RSAPublicKey) {
            if (alg == null) {
                return KeyEncryptionAlgorithm.RSA_OAEP_256.getAlgorithm();
            } else {
                return alg;
            }
        } else if (keyEncryptionKey instanceof SecretKey) {
            if (alg == null) {
                return KeyEncryptionAlgorithm.A256KW.getAlgorithm();
            } else {
                return alg;
            }
        } else if (keyEncryptionKey instanceof ECPublicKey) {
            if (alg == null) {
                return KeyEncryptionAlgorithm.ECDH_ES_A256KW.getAlgorithm();
            } else {
                return alg;
            }
        }

        throw new JwtEncryptionException("Unsupported key encryption algorithm: " + keyEncryptionKey.getAlgorithm());
    }

    private String getContentEncryptionAlgorithm() {
        return headers.containsKey("enc") ? headers.get("enc").toString() : ContentEncryptionAlgorithm.A256GCM.name();
    }

    static Key getKeyEncryptionKeyFromConfig(String kid) {
        try {
            String keyLocation = ConfigProvider.getConfig().getValue("smallrye.jwt.encrypt.key-location", String.class);
            try {
                return KeyUtils.readEncryptionKey(keyLocation, kid);
            } catch (Exception ex) {
                throw new JwtEncryptionException("Key encrypting key can not be loaded from: " + keyLocation);
            }
        } catch (NoSuchElementException ex) {
            throw new JwtEncryptionException("Please set a 'smallrye.jwt.encrypt.key-location' property");
        }
    }

    private static KeyEncryptionAlgorithm toKeyEncryptionAlgorithm(String value) {
        try {
            return KeyEncryptionAlgorithm.fromAlgorithm(value);
        } catch (Exception ex) {
            throw new JwtEncryptionException("Unsupported key encryption algorithm: " + value);
        }
    }

    private static ContentEncryptionAlgorithm toContentEncryptionAlgorithm(String value) {
        try {
            return ContentEncryptionAlgorithm.fromAlgorithm(value);
        } catch (Exception ex) {
            throw new JwtEncryptionException("Unsupported content encryption algorithm: " + value);
        }
    }
}