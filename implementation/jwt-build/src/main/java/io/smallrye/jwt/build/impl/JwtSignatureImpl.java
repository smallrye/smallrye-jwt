package io.smallrye.jwt.build.impl;

import java.security.Key;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;

import javax.crypto.SecretKey;

import org.eclipse.microprofile.config.ConfigProvider;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;

import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.build.JwtEncryptionBuilder;
import io.smallrye.jwt.build.JwtSignature;
import io.smallrye.jwt.build.JwtSignatureException;
import io.smallrye.jwt.util.KeyUtils;

/**
 * Default JWT Signature implementation
 */
class JwtSignatureImpl implements JwtSignature {
    JwtClaims claims = new JwtClaims();
    Map<String, Object> headers = new HashMap<>();
    Long tokenLifespan;

    JwtSignatureImpl() {
    }

    JwtSignatureImpl(JwtClaims claims) {
        this.claims = claims;
    }

    /**
     * {@inheritDoc}
     */
    public String sign(PrivateKey signingKey) throws JwtSignatureException {
        return signInternal(signingKey);
    }

    /**
     * {@inheritDoc}
     */
    public String sign(SecretKey signingKey) throws JwtSignatureException {
        return signInternal(signingKey);
    }

    /**
     * {@inheritDoc}
     */
    public String sign(String keyLocation) throws JwtSignatureException {
        try {
            return signInternal(getSigningKeyFromKeyLocation(keyLocation));
        } catch (JwtSignatureException ex) {
            throw ex;
        } catch (Exception ex) {
            throw ImplMessages.msg.signatureException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    public String sign() throws JwtSignatureException {
        try {
            Key key = null;
            if (!"none".equals(headers.get("alg"))) {
                key = getSigningKeyFromKeyLocation(getKeyLocationFromConfig());
            }
            return signInternal(key);
        } catch (JwtSignatureException ex) {
            throw ex;
        } catch (Exception ex) {
            throw ImplMessages.msg.signatureException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String signWithSecret(String secret) throws JwtSignatureException {
        return sign(KeyUtils.createSecretKeyFromSecret(secret));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtEncryptionBuilder innerSign(PrivateKey signingKey) throws JwtSignatureException {
        return new JwtEncryptionImpl(sign(signingKey), true);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtEncryptionBuilder innerSign(SecretKey signingKey) throws JwtSignatureException {
        return new JwtEncryptionImpl(sign(signingKey), true);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtEncryptionBuilder innerSign(String keyLocation) throws JwtSignatureException {
        return new JwtEncryptionImpl(sign(keyLocation), true);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtEncryptionBuilder innerSign() throws JwtSignatureException {

        if (!signingKeyConfigured()) {
            if (headers.containsKey("alg") && !"none".equals(headers.get("alg"))) {
                throw ImplMessages.msg.signKeyPropertyRequired(headers.get("alg").toString());
            }
            if (headers.containsKey("kid")) {
                throw ImplMessages.msg.signAlgorithmRequired();
            }
            headers.put("alg", AlgorithmIdentifiers.NONE);
        }
        return new JwtEncryptionImpl(sign(), true);
    }

    @Override
    public JwtEncryptionBuilder innerSignWithSecret(String secret) throws JwtSignatureException {
        return innerSign(KeyUtils.createSecretKeyFromSecret(secret));
    }

    private static boolean signingKeyConfigured() {
        try {
            ConfigProvider.getConfig().getValue("smallrye.jwt.sign.key-location", String.class);
            return true;
        } catch (NoSuchElementException ex) {
            return false;
        }
    }

    private String signInternal(Key signingKey) {
        JwtBuildUtils.setDefaultJwtClaims(claims, tokenLifespan);
        JsonWebSignature jws = new JsonWebSignature();
        for (Map.Entry<String, Object> entry : headers.entrySet()) {
            jws.setHeader(entry.getKey(), entry.getValue());
        }
        if (!headers.containsKey("typ")) {
            jws.setHeader("typ", "JWT");
        }
        String algorithm = (String) headers.get("alg");
        if (algorithm == null) {
            algorithm = keyAlgorithm(headers, signingKey);
            jws.setAlgorithmHeaderValue(algorithm);
        }
        if ("none".equals(algorithm)) {
            jws.setAlgorithmConstraints(AlgorithmConstraints.ALLOW_ONLY_NONE);
        }
        jws.setPayload(claims.toJson());
        jws.setKey(signingKey);
        try {
            return jws.getCompactSerialization();
        } catch (Exception ex) {
            throw ImplMessages.msg.signJwtTokenFailed(ex.getMessage(), ex);
        }
    }

    static String keyAlgorithm(Map<String, Object> headers, Key signingKey) {
        String alg = (String) headers.get("alg");
        if (signingKey instanceof RSAPrivateKey) {
            if (alg == null) {
                return SignatureAlgorithm.RS256.name();
            } else if (alg.startsWith("RS")) {
                return alg;
            }
        } else if (signingKey instanceof ECPrivateKey) {
            if (alg == null) {
                return SignatureAlgorithm.ES256.name();
            } else if (alg.startsWith("ES")) {
                return alg;
            }
        } else if (signingKey instanceof SecretKey) {
            if (alg == null) {
                return SignatureAlgorithm.HS256.name();
            } else if (alg.startsWith("HS")) {
                return alg;
            }
        }
        throw ImplMessages.msg.unsupportedSignatureAlgorithm(signingKey.getAlgorithm());
    }

    static String getKeyLocationFromConfig() {
        String keyLocation = JwtBuildUtils.getConfigProperty("smallrye.jwt.sign.key-location", String.class);
        if (keyLocation == null) {
            throw ImplMessages.msg.signKeyLocationNotConfigured();
        }
        return keyLocation;
    }

    Key getSigningKeyFromKeyLocation(String keyLocation) {
        try {
            Key key = KeyUtils.readSigningKey(keyLocation, (String) headers.get("kid"));
            if (key == null) {
                throw ImplMessages.msg.signingKeyCanNotBeLoadedFromLocation(keyLocation);
            }
            return key;
        } catch (Exception ex) {
            throw ImplMessages.msg.signingKeyCanNotBeLoadedFromLocation(keyLocation);
        }

    }
}