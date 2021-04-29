package io.smallrye.jwt.build.impl;

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

/**
 * Default JWT Encryption implementation
 */
class JwtEncryptionImpl implements JwtEncryptionBuilder {
    private static final String KEY_LOCATION_PROPERTY = "smallrye.jwt.encrypt.key.location";

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
            return encryptInternal(getEncryptionKeyFromKeyLocation(keyLocation));
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
            return encryptInternal(getEncryptionKeyFromKeyLocation(getKeyLocationFromConfig()));
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

        if (key instanceof RSAPublicKey && keyAlgorithm.startsWith(KeyEncryptionAlgorithm.RSA_OAEP.getAlgorithm())
                && ((RSAPublicKey) key).getModulus().bitLength() < 2048) {
            throw ImplMessages.msg.encryptionKeySizeMustBeHigher(keyAlgorithm);
        }
        jwe.setKey(key);
        try {
            return jwe.getCompactSerialization();
        } catch (org.jose4j.lang.JoseException ex) {
            throw ImplMessages.msg.joseSerializationError(ex.getMessage(), ex);
        }
    }

    private String getKeyEncryptionAlgorithm(Key keyEncryptionKey) {
        String alg = (String) headers.get("alg");
        if ("dir".equals(alg)) {
            throw ImplMessages.msg.directContentEncryptionUnsupported();
        }
        if (alg == null) {
            if (keyEncryptionKey instanceof RSAPublicKey) {
                alg = KeyEncryptionAlgorithm.RSA_OAEP_256.getAlgorithm();
            } else if (keyEncryptionKey instanceof SecretKey) {
                alg = KeyEncryptionAlgorithm.A256KW.getAlgorithm();
            } else if (keyEncryptionKey instanceof ECPublicKey) {
                alg = KeyEncryptionAlgorithm.ECDH_ES_A256KW.getAlgorithm();
            }
        }
        if (alg == null) {
            throw ImplMessages.msg.unsupportedKeyEncryptionAlgorithm(keyEncryptionKey.getAlgorithm());
        }
        return alg;
    }

    private String getContentEncryptionAlgorithm() {
        return headers.containsKey("enc") ? headers.get("enc").toString() : ContentEncryptionAlgorithm.A256GCM.name();
    }

    private static String getKeyLocationFromConfig() {
        String keyLocation = JwtBuildUtils.getConfigProperty(KEY_LOCATION_PROPERTY, String.class);
        if (keyLocation != null) {
            return keyLocation;
        }
        throw ImplMessages.msg.encryptionKeyLocationNotConfigured();
    }

    Key getEncryptionKeyFromKeyLocation(String keyLocation) {
        try {
            String kid = (String) headers.get("kid");
            String algHeader = (String) headers.get("alg");

            String keyContent = KeyUtils.readKeyContent(keyLocation);
            // Try PEM format first - default to RSA_OAEP_256 if no algorithm header is set
            Key key = KeyUtils.tryAsPemEncryptionPublicKey(keyContent,
                    (algHeader == null ? KeyEncryptionAlgorithm.RSA_OAEP_256
                            : KeyEncryptionAlgorithm.fromAlgorithm(algHeader)));
            if (key == null) {
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
                throw ImplMessages.msg.encryptionKeyCanNotBeLoadedFromLocation(keyLocation);
            }
            return key;
        } catch (Exception ex) {
            throw ImplMessages.msg.encryptionKeyCanNotBeLoadedFromLocation(keyLocation);
        }
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
