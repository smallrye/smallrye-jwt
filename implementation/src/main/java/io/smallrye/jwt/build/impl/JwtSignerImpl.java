package io.smallrye.jwt.build.impl;

import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import org.jose4j.jwt.JwtClaims;

import io.smallrye.jwt.build.JwtException;
import io.smallrye.jwt.build.JwtSigner;

/**
 * Default JWT Signer implementation
 */
class JwtSignerImpl implements JwtSigner {
    JwtClaims claims = new JwtClaims();
    Map<String, Object> headers = new HashMap<>();

    JwtSignerImpl() {
    }

    JwtSignerImpl(JwtClaims claims) {
        this.claims = claims;
    }

    /**
     * {@inheritDoc}
     */
    public String sign(PrivateKey signingKey) throws JwtException {
        return JwtSigningUtils.signJwtClaimsInternal(signingKey, headers, claims);
    }

    /**
     * {@inheritDoc}
     */
    public String sign(SecretKey signingKey) throws JwtException {
        return JwtSigningUtils.signJwtClaimsInternal(signingKey, headers, claims);
    }

    /**
     * {@inheritDoc}
     */
    public String sign() throws JwtException {
        return JwtSigningUtils.signJwtClaimsInternal(JwtSigningUtils.getSigningKeyFromConfig(), headers, claims);
    }
}