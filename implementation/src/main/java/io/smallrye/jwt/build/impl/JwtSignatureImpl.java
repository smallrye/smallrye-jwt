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

import io.smallrye.jwt.KeyUtils;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.build.JwtEncryptionBuilder;
import io.smallrye.jwt.build.JwtSignature;
import io.smallrye.jwt.build.JwtSignatureException;

/**
 * Default JWT Signature implementation
 */
class JwtSignatureImpl implements JwtSignature {
    JwtClaims claims = new JwtClaims();
    Map<String, Object> headers = new HashMap<>();

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
        Key key = null;
        try {
            key = KeyUtils.readSigningKey(keyLocation, (String) headers.get("kid"));
        } catch (Exception ex) {
            throw ImplMessages.msg.signatureException(ex);
        }
        return key instanceof PrivateKey ? sign((PrivateKey) key) : sign((SecretKey) key);

    }

    /**
     * {@inheritDoc}
     */
    public String sign() throws JwtSignatureException {
        Key signingKey = "none".equals(headers.get("alg")) ? null : getSigningKeyFromConfig((String) headers.get("kid"));
        return signInternal(signingKey);
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

    private static boolean signingKeyConfigured() {
        try {
            ConfigProvider.getConfig().getValue("smallrye.jwt.sign.key-location", String.class);
            return true;
        } catch (NoSuchElementException ex) {
            return false;
        }
    }

    private String signInternal(Key signingKey) {
        JwtBuildUtils.setDefaultJwtClaims(claims);
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
        if (signingKey instanceof RSAPrivateKey && algorithm.startsWith("RS")
                && ((RSAPrivateKey) signingKey).getModulus().bitLength() < 2048) {
            throw ImplMessages.msg.signKeySizeMustBeHigher(algorithm);
        }
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

    static Key getSigningKeyFromConfig(String kid) {
        String keyLocation = JwtBuildUtils.getConfigProperty("smallrye.jwt.sign.key-location", String.class);
        if (keyLocation != null) {
            try {
                return KeyUtils.readSigningKey(keyLocation, kid);
            } catch (Exception ex) {
                throw ImplMessages.msg.signingKeyCanNotBeLoadedFromLocation(keyLocation);
            }
        } else {
            throw ImplMessages.msg.signKeyLocationNotConfigured();
        }
    }
}