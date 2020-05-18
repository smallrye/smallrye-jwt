package io.smallrye.jwt.build.impl;

import java.security.Key;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;

import javax.crypto.SecretKey;

import org.eclipse.microprofile.config.ConfigProvider;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;

import io.smallrye.jwt.KeyUtils;
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
        return JwtSigningUtils.signJwtClaimsInternal(signingKey, headers, claims);
    }

    /**
     * {@inheritDoc}
     */
    public String sign(SecretKey signingKey) throws JwtSignatureException {
        return JwtSigningUtils.signJwtClaimsInternal(signingKey, headers, claims);
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
        return JwtSigningUtils.signJwtClaimsInternal(headers, claims);
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
}