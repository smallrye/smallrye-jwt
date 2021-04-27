package io.smallrye.jwt.build.impl;

import java.security.Key;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.JsonWebKey;
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
    private static final String KEY_LOCATION_PROPERTY = "smallrye.jwt.sign.key.location";

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
            Key key = getSigningKeyFromKeyLocation(getKeyLocationFromConfig());
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

        return new JwtEncryptionImpl(sign(), true);
    }

    @Override
    public JwtEncryptionBuilder innerSignWithSecret(String secret) throws JwtSignatureException {
        return innerSign(KeyUtils.createSecretKeyFromSecret(secret));
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
        if ("none".equals(algorithm)) {
            jws.setAlgorithmConstraints(AlgorithmConstraints.ALLOW_ONLY_NONE);
        } else {
            algorithm = keyAlgorithm(headers, signingKey, algorithm);
        }
        jws.setAlgorithmHeaderValue(algorithm);

        jws.setPayload(claims.toJson());
        jws.setKey(signingKey);
        try {
            return jws.getCompactSerialization();
        } catch (Exception ex) {
            throw ImplMessages.msg.signJwtTokenFailed(ex.getMessage(), ex);
        }
    }

    static String keyAlgorithm(Map<String, Object> headers, Key signingKey, String alg) {
        if (signingKey instanceof RSAPrivateKey) {
            if (alg == null) {
                return SignatureAlgorithm.RS256.name();
            } else if (alg.startsWith("RS") || alg.startsWith("PS")) {
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
        String keyLocation = JwtBuildUtils.getConfigProperty(KEY_LOCATION_PROPERTY, String.class);
        if (keyLocation != null) {
            return keyLocation;
        }
        throw ImplMessages.msg.signKeyLocationNotConfigured();
    }

    Key getSigningKeyFromKeyLocation(String keyLocation) {
        try {
            String kid = (String) headers.get("kid");
            String algHeader = (String) headers.get("alg");

            String keyContent = KeyUtils.readKeyContent(keyLocation);
            // Try PEM format first - default to RS256 if no algorithm header is set
            Key key = KeyUtils.tryAsPemSigningPrivateKey(keyContent,
                    (algHeader == null ? SignatureAlgorithm.RS256 : SignatureAlgorithm.fromAlgorithm(algHeader)));
            if (key == null) {
                // Try to load JWK from a single JWK resource or JWK set resource
                JsonWebKey jwk = KeyUtils.getJwkKeyFromJwkSet(kid, keyContent);
                if (jwk != null) {
                    // if the user has already set the algorithm header then JWK `alg` header, if set, must match it
                    key = KeyUtils.getPrivateOrSecretSigningKey(jwk,
                            (algHeader == null ? null : SignatureAlgorithm.fromAlgorithm(algHeader)));
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
                throw ImplMessages.msg.signingKeyCanNotBeLoadedFromLocation(keyLocation);
            }
            return key;
        } catch (Exception ex) {
            throw ImplMessages.msg.signingKeyCanNotBeLoadedFromLocation(keyLocation);
        }

    }
}