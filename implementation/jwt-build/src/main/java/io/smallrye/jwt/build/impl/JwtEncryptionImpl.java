package io.smallrye.jwt.build.impl;

import java.io.InputStream;
import java.security.Key;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwk.JsonWebKey;

import io.smallrye.jwt.algorithm.ContentEncryptionAlgorithm;
import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.jwt.build.JwtEncryptionBuilder;
import io.smallrye.jwt.build.JwtEncryptionException;
import io.smallrye.jwt.util.KeyUtils;
import io.smallrye.jwt.util.ResourceUtils;

/**
 * Default JWT Encryption implementation
 */
class JwtEncryptionImpl implements JwtEncryptionBuilder {
    private static final String XEC_PUBLIC_KEY_INTERFACE = "java.security.interfaces.XECPublicKey";

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

    /**
     * {@inheritDoc}
     */
    @Override
    public String encrypt(PublicKey keyEncryptionKey) throws JwtEncryptionException {
        return encryptInternal(keyEncryptionKey);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String encrypt(SecretKey keyEncryptionKey) throws JwtEncryptionException {
        return encryptInternal(keyEncryptionKey);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String encrypt(String keyLocation) throws JwtEncryptionException {
        try {
            return encryptInternal(getEncryptionKeyFromKeyContent(getKeyContentFromLocation(keyLocation)));
        } catch (JwtEncryptionException ex) {
            throw ex;
        } catch (Exception ex) {
            throw ImplMessages.msg.encryptionException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String encrypt() throws JwtEncryptionException {
        try {
            Key key = null;

            String keyLocation = JwtBuildUtils.getConfigProperty(JwtBuildUtils.ENC_KEY_LOCATION_PROPERTY, String.class);
            if (keyLocation != null) {
                key = JwtBuildUtils.readPublicKeyFromKeystore(keyLocation.trim());
                if (key == null) {
                    try (InputStream keyStream = ResourceUtils.getResourceStream(keyLocation.trim())) {
                        key = getEncryptionKeyFromKeyContent(new String(ResourceUtils.readBytes(keyStream)));
                    }
                }
            } else {
                key = JwtBuildUtils.readPublicKeyFromKeystore(null);
                if (key == null) {
                    String keyContent = JwtBuildUtils.getConfigProperty(JwtBuildUtils.ENC_KEY_PROPERTY, String.class);
                    if (keyContent != null) {
                        key = getEncryptionKeyFromKeyContent(keyContent);
                    } else {
                        throw ImplMessages.msg.encryptionKeyNotConfigured();
                    }
                }
            }
            if (key == null) {
                throw ImplMessages.msg.encryptionKeyCanNotBeCreatedFromContent();
            }
            return encryptInternal(key);
        } catch (JwtEncryptionException ex) {
            throw ex;
        } catch (Exception ex) {
            throw ImplMessages.msg.encryptionException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String encryptWithSecret(String secret) throws JwtEncryptionException {
        return encrypt(KeyUtils.createSecretKeyFromSecret(secret));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtEncryptionBuilder header(String name, Object value) {
        if ("alg".equals(name)) {
            return keyAlgorithm(toKeyEncryptionAlgorithm((String) value));
        } else if ("enc".equals(name)) {
            return contentAlgorithm(toContentEncryptionAlgorithm((String) value));
        } else {
            headers.put(name, value);
            return this;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtEncryptionBuilder keyAlgorithm(KeyEncryptionAlgorithm algorithm) {
        headers.put("alg", algorithm.getAlgorithm());
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtEncryptionBuilder contentAlgorithm(ContentEncryptionAlgorithm algorithm) {
        headers.put("enc", algorithm.getAlgorithm());
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtEncryptionBuilder keyId(String keyId) {
        headers.put("kid", keyId);
        return this;
    }

    private String encryptInternal(Key key) {
        if (key == null) {
            throw ImplMessages.msg.encryptionKeyIsNull();
        }

        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setPlaintext(claims);
        for (Map.Entry<String, Object> entry : headers.entrySet()) {
            jwe.getHeaders().setObjectHeaderValue(entry.getKey(), entry.getValue());
        }
        if (innerSigned && !headers.containsKey("cty")) {
            jwe.getHeaders().setObjectHeaderValue("cty", "JWT");
        }
        String keyAlgorithm = getKeyEncryptionAlgorithm(key);
        jwe.setAlgorithmHeaderValue(keyAlgorithm);
        jwe.setEncryptionMethodHeaderParameter(getContentEncryptionAlgorithm());
        jwe.setKey(key);
        if (isRelaxKeyValidation()) {
            jwe.setDoKeyValidation(false);
        }
        try {
            return jwe.getCompactSerialization();
        } catch (org.jose4j.lang.JoseException ex) {
            throw ImplMessages.msg.joseSerializationError(ex.getMessage(), ex);
        }
    }

    private boolean isRelaxKeyValidation() {
        return JwtBuildUtils.getConfigProperty(JwtBuildUtils.ENC_KEY_RELAX_VALIDATION_PROPERTY, Boolean.class, false);
    }

    private String getKeyEncryptionAlgorithm(Key keyEncryptionKey) {
        String alg = (String) headers.get("alg");
        if (alg == null) {
            try {
                alg = JwtBuildUtils.getConfigProperty(JwtBuildUtils.NEW_TOKEN_KEY_ENCRYPTION_ALG_PROPERTY, String.class);
                if (alg != null) {
                    alg = KeyEncryptionAlgorithm.fromAlgorithm(alg).getAlgorithm();
                }
            } catch (Exception ex) {
                throw ImplMessages.msg.unsupportedKeyEncryptionAlgorithm(alg);
            }
        }

        if (keyEncryptionKey instanceof RSAPublicKey) {
            if (alg == null) {
                return KeyEncryptionAlgorithm.RSA_OAEP.getAlgorithm();
            } else if (alg.startsWith("RS")) {
                return alg;
            }
        } else if (keyEncryptionKey instanceof ECPublicKey || isXecPublicKey(keyEncryptionKey)) {
            if (alg == null) {
                return KeyEncryptionAlgorithm.ECDH_ES_A256KW.getAlgorithm();
            } else if (alg.startsWith("EC")) {
                return alg;
            }
        } else if (keyEncryptionKey instanceof SecretKey) {
            if (alg == null) {
                return KeyEncryptionAlgorithm.A256KW.getAlgorithm();
            } else if (alg.startsWith("A") || alg.startsWith("PBE") || KeyEncryptionAlgorithm.DIR.getAlgorithm().equals(alg)) {
                return alg;
            }
        }
        throw ImplMessages.msg.unsupportedKeyEncryptionAlgorithm(keyEncryptionKey.getAlgorithm());
    }

    private static boolean isXecPublicKey(Key encKey) {
        return KeyUtils.isSupportedKey(encKey, XEC_PUBLIC_KEY_INTERFACE);
    }

    private String getContentEncryptionAlgorithm() {
        String alg = (String) headers.get("enc");
        if (alg == null) {
            try {
                alg = JwtBuildUtils.getConfigProperty(JwtBuildUtils.NEW_TOKEN_CONTENT_ENCRYPTION_ALG_PROPERTY, String.class);
                if (alg != null) {
                    alg = ContentEncryptionAlgorithm.fromAlgorithm(alg).getAlgorithm();
                }
            } catch (Exception ex) {
                throw ImplMessages.msg.unsupportedContentEncryptionAlgorithm(alg);
            }
        }
        return alg != null ? alg : ContentEncryptionAlgorithm.A256GCM.name();
    }

    private static String getKeyContentFromLocation(String keyLocation) {
        try {
            return KeyUtils.readKeyContent(keyLocation);
        } catch (Exception ex) {
            throw ImplMessages.msg.encryptionKeyCanNotBeLoadedFromLocation(keyLocation);
        }
    }

    Key getEncryptionKeyFromKeyContent(String keyContent) {
        String kid = (String) headers.get("kid");
        String algHeader = (String) headers.get("alg");

        // Try PEM format first - default to RSA_OAEP_256 if no algorithm header is set
        Key key = KeyUtils.tryAsPemEncryptionPublicKey(keyContent,
                (algHeader == null ? KeyEncryptionAlgorithm.RSA_OAEP_256
                        : KeyEncryptionAlgorithm.fromAlgorithm(algHeader)));
        if (key == null) {
            if (kid == null) {
                kid = JwtBuildUtils.getConfigProperty(JwtBuildUtils.ENC_KEY_ID_PROPERTY, String.class);
                if (kid != null) {
                    headers.put("kid", kid);
                }
            }
            // Try to load JWK from a single JWK resource or JWK set resource
            JsonWebKey jwk = KeyUtils.getJwkKeyFromJwkSet(kid, keyContent);
            if (jwk != null) {
                // if the user has already set the algorithm header then JWK `alg` header, if set, must match it
                key = KeyUtils.getPublicOrSecretEncryptingKey(jwk,
                        (algHeader == null ? null : KeyEncryptionAlgorithm.fromAlgorithm(algHeader)));
                if (key != null) {
                    // if the algorithm header is not set then use JWK `alg`
                    if (algHeader == null && jwk.getAlgorithm() != null) {
                        headers.put("alg", jwk.getAlgorithm());
                    }
                    // if 'kid' header is not set then use JWK `kid`
                    if (kid == null && jwk.getKeyId() != null) {
                        headers.put("kid", jwk.getKeyId());
                    }
                }
            }
        }
        if (key == null) {
            throw ImplMessages.msg.encryptionKeyCanNotBeCreatedFromContent();
        }
        return key;
    }

    private static KeyEncryptionAlgorithm toKeyEncryptionAlgorithm(String value) {
        try {
            return KeyEncryptionAlgorithm.fromAlgorithm(value);
        } catch (Exception ex) {
            throw ImplMessages.msg.unsupportedKeyEncryptionAlgorithm(value);
        }
    }

    private static ContentEncryptionAlgorithm toContentEncryptionAlgorithm(String value) {
        try {
            return ContentEncryptionAlgorithm.fromAlgorithm(value);
        } catch (Exception ex) {
            throw ImplMessages.msg.unsupportedContentEncryptionAlgorithm(value);
        }
    }
}
