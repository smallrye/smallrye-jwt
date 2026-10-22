package io.smallrye.jwt.build.impl;

import java.io.InputStream;
import java.security.Key;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.XECPublicKey;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import com.nimbusds.jose.HeaderParameterNames;

import io.smallrye.jwe.JweEncrypter;
import io.smallrye.jwe.JweException;
import io.smallrye.jwk.JsonWebKey;
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
                    InputStream is = ResourceUtils.getResourceStream(keyLocation.trim());
                    if (is != null) {
                        try (InputStream keyStream = is) {
                            key = getEncryptionKeyFromKeyContent(new String(ResourceUtils.readBytes(keyStream)));
                        }
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
        if (HeaderParameterNames.ALGORITHM.equals(name)) {
            return keyAlgorithm(toKeyEncryptionAlgorithm((String) value));
        } else if (HeaderParameterNames.ENCRYPTION_ALGORITHM.equals(name)) {
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
        headers.put(HeaderParameterNames.ALGORITHM, algorithm.getAlgorithm());
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtEncryptionBuilder contentAlgorithm(ContentEncryptionAlgorithm algorithm) {
        headers.put(HeaderParameterNames.ENCRYPTION_ALGORITHM, algorithm.getAlgorithm());
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtEncryptionBuilder keyId(String keyId) {
        headers.put(HeaderParameterNames.KEY_ID, keyId);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtEncryptionBuilder type(String type) {
        headers.put(HeaderParameterNames.TYPE, type);
        return this;
    }

    private String encryptInternal(Key key) {
        if (key == null) {
            throw ImplMessages.msg.encryptionKeyIsNull();
        }

        JweEncrypter.Builder encrypterBuilder = JweEncrypter.builder(key)
                .keyAlgorithm(KeyEncryptionAlgorithm.fromAlgorithm(getKeyEncryptionAlgorithm(key)))
                .contentAlgorithm(ContentEncryptionAlgorithm.fromAlgorithm(getContentEncryptionAlgorithm()))
                .relaxKeyValidation(isRelaxKeyValidation())
                .headers(headers);

        if (innerSigned && !headers.containsKey(HeaderParameterNames.CONTENT_TYPE)) {
            encrypterBuilder.contentType("JWT");
        }

        try {
            return encrypterBuilder.build().encrypt(claims);
        } catch (JweException ex) {
            throw ImplMessages.msg.joseSerializationError(ex.getMessage(), ex);
        }
    }

    private boolean isRelaxKeyValidation() {
        return JwtBuildUtils.getConfigProperty(JwtBuildUtils.ENC_KEY_RELAX_VALIDATION_PROPERTY, Boolean.class,
                Boolean.FALSE);
    }

    private String getConfiguredKeyEncryptionAlgorithm() {
        String alg = (String) headers.get(HeaderParameterNames.ALGORITHM);
        if (alg == null) {
            try {
                alg = JwtBuildUtils.getConfigProperty(JwtBuildUtils.NEW_TOKEN_KEY_ENCRYPTION_ALG_PROPERTY, String.class);
                if (alg != null) {
                    alg = KeyEncryptionAlgorithm.fromAlgorithm(alg).getAlgorithm();
                    headers.put(HeaderParameterNames.ALGORITHM, alg);
                }
            } catch (Exception ex) {
                throw ImplMessages.msg.unsupportedKeyEncryptionAlgorithm(alg);
            }
        }
        return alg;
    }

    private String getKeyEncryptionAlgorithm(Key keyEncryptionKey) {
        String alg = getConfiguredKeyEncryptionAlgorithm();

        if (keyEncryptionKey instanceof RSAPublicKey) {
            if (alg == null) {
                return KeyEncryptionAlgorithm.RSA_OAEP.getAlgorithm();
            } else if (alg.startsWith("RS")) {
                return alg;
            }
        } else if (keyEncryptionKey instanceof ECPublicKey || keyEncryptionKey instanceof XECPublicKey) {
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

    private String getContentEncryptionAlgorithm() {
        String alg = (String) headers.get(HeaderParameterNames.ENCRYPTION_ALGORITHM);
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
        String kid = (String) headers.get(HeaderParameterNames.KEY_ID);
        String alg = getConfiguredKeyEncryptionAlgorithm();

        // Try PEM format first - default to RSA_OAEP_256 if no algorithm header is set
        Key key = KeyUtils.tryAsPemEncryptionPublicKey(keyContent,
                (alg == null ? KeyEncryptionAlgorithm.RSA_OAEP_256 : KeyEncryptionAlgorithm.fromAlgorithm(alg)));
        if (key == null) {
            if (kid == null) {
                kid = JwtBuildUtils.getConfigProperty(JwtBuildUtils.ENC_KEY_ID_PROPERTY, String.class);
                if (kid != null) {
                    headers.put(HeaderParameterNames.KEY_ID, kid);
                }
            }
            // Try to load JWK from a single JWK resource or JWK set resource
            JsonWebKey jwk = KeyUtils.getJwkKeyFromJwkSet(kid, keyContent);
            if (jwk != null) {
                // if the user has already set the algorithm header then JWK `alg` header, if set, must match it
                key = KeyUtils.getPublicOrSecretEncryptingKey(jwk,
                        (alg == null ? null : KeyEncryptionAlgorithm.fromAlgorithm(alg)));
                if (key != null) {
                    // if the algorithm header is not set then use JWK `alg`
                    if (alg == null && jwk.algorithm() != null) {
                        headers.put(HeaderParameterNames.ALGORITHM, jwk.algorithm());
                    }
                    // if 'kid' header is not set then use JWK `kid`
                    if (kid == null && jwk.keyId() != null) {
                        headers.put(HeaderParameterNames.KEY_ID, jwk.keyId());
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
