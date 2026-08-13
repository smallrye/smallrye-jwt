package io.smallrye.jwt.build.impl;

import java.io.InputStream;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import org.eclipse.microprofile.jwt.Claims;

import com.nimbusds.jose.HeaderParameterNames;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;

import io.smallrye.jwt.algorithm.EdDSASigner;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.build.JwtEncryptionBuilder;
import io.smallrye.jwt.build.JwtSignature;
import io.smallrye.jwt.build.JwtSignatureException;
import io.smallrye.jwt.common.JwtClaims;
import io.smallrye.jwt.util.KeyUtils;
import io.smallrye.jwt.util.ResourceUtils;

/**
 * Default JWT Signature implementation
 */
class JwtSignatureImpl implements JwtSignature {

    JwtClaims claims = new JwtClaims();
    Map<String, Object> headers = new HashMap<>();
    Long tokenLifespan;
    Key configuredPemKey;

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
            return signInternal(getSigningKeyFromKeyContent(getKeyContentFromLocation(keyLocation)));
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
            Key key = configuredPemKey;
            if (key == null) {
                String keyLocation = JwtBuildUtils.getConfigProperty(JwtBuildUtils.SIGN_KEY_LOCATION_PROPERTY, String.class);
                if (keyLocation != null) {
                    key = JwtBuildUtils.readPrivateKeyFromKeystore(keyLocation.trim());
                    if (key == null) {
                        InputStream is = ResourceUtils.getResourceStream(keyLocation.trim());
                        if (is != null) {
                            try (InputStream keyStream = is) {
                                key = getSigningKeyFromKeyContent(new String(ResourceUtils.readBytes(keyStream)));
                            }
                        }
                    }
                } else {
                    key = JwtBuildUtils.readPrivateKeyFromKeystore(null);
                    if (key == null) {
                        String keyContent = JwtBuildUtils.getConfigProperty(JwtBuildUtils.SIGN_KEY_PROPERTY, String.class);
                        if (keyContent != null) {
                            key = getSigningKeyFromKeyContent(keyContent);
                        } else {
                            throw ImplMessages.msg.signKeyNotConfigured();
                        }
                    }
                }
            }
            if (key == null) {
                throw ImplMessages.msg.signingKeyCanNotBeCreatedFromContent();
            }

            return signInternal(key);
        } catch (JwtSignatureException ex) {
            throw ex;
        } catch (Exception ex) {
            throw ImplMessages.msg.signatureException(ex);
        } finally {
            removeJti();
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
        try {
            return new JwtEncryptionImpl(sign(), true);
        } finally {
            removeJti();
        }
    }

    @Override
    public JwtEncryptionBuilder innerSignWithSecret(String secret) throws JwtSignatureException {
        return innerSign(KeyUtils.createSecretKeyFromSecret(secret));
    }

    private String signInternal(Key signingKey) {
        if (signingKey == null) {
            throw ImplMessages.msg.signingKeyIsNull();
        }
        JwtBuildUtils.setDefaultJwtClaims(claims, tokenLifespan);

        String algorithm = getSignatureAlgorithm(signingKey);

        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.parse(algorithm));

        if (!headers.containsKey(HeaderParameterNames.TYPE)) {
            headerBuilder.type(new JOSEObjectType("JWT"));
        }

        for (Map.Entry<String, Object> entry : headers.entrySet()) {
            String name = entry.getKey();
            Object value = entry.getValue();
            switch (name) {
                case HeaderParameterNames.ALGORITHM:
                    // already set
                    break;
                case HeaderParameterNames.KEY_ID:
                    headerBuilder.keyID((String) value);
                    break;
                case HeaderParameterNames.TYPE:
                    headerBuilder.type(new JOSEObjectType((String) value));
                    break;
                case HeaderParameterNames.X_509_CERT_SHA_1_THUMBPRINT:
                    headerBuilder.x509CertThumbprint(new Base64URL((String) value));
                    break;
                case HeaderParameterNames.X_509_CERT_SHA_256_THUMBPRINT:
                    headerBuilder.x509CertSHA256Thumbprint(new Base64URL((String) value));
                    break;
                case HeaderParameterNames.X_509_CERT_CHAIN:
                    @SuppressWarnings("unchecked")
                    List<String> chain = (List<String>) value;
                    headerBuilder.x509CertChain(
                            chain.stream().map(Base64::new)
                                    .collect(Collectors.toList()));
                    break;
                case HeaderParameterNames.JWK:
                    if (value instanceof Map) {
                        try {
                            @SuppressWarnings("unchecked")
                            Map<String, Object> jwkMap = (Map<String, Object>) value;
                            headerBuilder.jwk(JWK.parse(jwkMap));
                        } catch (ParseException e) {
                            throw ImplMessages.msg.signatureException(e);
                        }
                    }
                    break;
                default:
                    headerBuilder.customParam(name, value);
            }
        }

        JWSHeader header = headerBuilder.build();
        String payload = claims.toJsonString();
        JWSObject jws = new JWSObject(header, new Payload(payload));

        try {
            JWSSigner signer = createSigner(signingKey, isRelaxKeyValidation());
            jws.sign(signer);
            return jws.serialize();
        } catch (JOSEException | IllegalArgumentException ex) {
            throw ImplMessages.msg.signJwtTokenFailed(ex.getMessage(), ex);
        }
    }

    private boolean isRelaxKeyValidation() {
        return JwtBuildUtils.getConfigProperty(JwtBuildUtils.SIGN_KEY_RELAX_VALIDATION_PROPERTY, Boolean.class, Boolean.FALSE);
    }

    private JWSSigner createSigner(Key signingKey, boolean relaxValidation) throws JOSEException {
        if (signingKey instanceof RSAPrivateKey) {
            return new RSASSASigner((RSAPrivateKey) signingKey, relaxValidation);
        } else if (signingKey instanceof ECPrivateKey) {
            return new ECDSASigner((ECPrivateKey) signingKey);
        } else if (signingKey instanceof SecretKey) {
            return new MACSigner((SecretKey) signingKey);
        } else if (signingKey instanceof EdECPrivateKey) {
            return new EdDSASigner((PrivateKey) signingKey);
        }
        throw new JOSEException("Unsupported key type for signing: " + signingKey.getClass().getName());
    }

    private String getConfiguredSignatureAlgorithm() {
        String alg = (String) headers.get(HeaderParameterNames.ALGORITHM);
        if (alg == null) {
            try {
                alg = JwtBuildUtils.getConfigProperty(JwtBuildUtils.NEW_TOKEN_SIGNATURE_ALG_PROPERTY, String.class);
                if (alg != null) {
                    alg = SignatureAlgorithm.fromAlgorithm(alg).getAlgorithm();
                    headers.put(HeaderParameterNames.ALGORITHM, alg);
                }
            } catch (Exception ex) {
                throw ImplMessages.msg.unsupportedSignatureAlgorithm(alg, ex);
            }
        }
        return alg;
    }

    private String getSignatureAlgorithm(Key signingKey) {
        String alg = getConfiguredSignatureAlgorithm();
        if ("none".equals(alg)) {
            throw ImplMessages.msg.noneSignatureAlgorithmUnsupported();
        }
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
        } else if (signingKey instanceof PrivateKey) {
            if (signingKey instanceof EdECPrivateKey) {
                if (alg == null || alg.equals(SignatureAlgorithm.EDDSA.getAlgorithm())) {
                    return SignatureAlgorithm.EDDSA.getAlgorithm();
                }
            }
            if (alg == null) {
                return SignatureAlgorithm.RS256.name();
            } else if (alg.startsWith("RS") || alg.startsWith("PS") || alg.startsWith("ES")) {
                return alg;
            }
        }
        throw ImplMessages.msg.unsupportedSignatureAlgorithm(signingKey.getAlgorithm());
    }

    static String getKeyContentFromLocation(String keyLocation) {
        try {
            return KeyUtils.readKeyContent(keyLocation);
        } catch (Exception ex) {
            throw ImplMessages.msg.signingKeyCanNotBeLoadedFromLocation(keyLocation, ex);
        }
    }

    Key getSigningKeyFromKeyContent(String keyContent) {
        String kid = (String) headers.get(HeaderParameterNames.KEY_ID);
        String alg = getConfiguredSignatureAlgorithm();

        SignatureAlgorithm algorithm;
        try {
            algorithm = (alg == null ? null : SignatureAlgorithm.fromAlgorithm(alg));
        } catch (IllegalArgumentException ex) {
            throw ImplMessages.msg.unsupportedSignatureAlgorithm(alg, ex);
        }

        // Try PEM format first - default to RS256 if the algorithm is unknown
        Key key = KeyUtils.tryAsPemSigningPrivateKey(keyContent, algorithm == null ? SignatureAlgorithm.RS256 : algorithm);
        if (key == null) {
            if (kid == null) {
                kid = JwtBuildUtils.getConfigProperty(JwtBuildUtils.SIGN_KEY_ID_PROPERTY, String.class);
                if (kid != null) {
                    headers.put(HeaderParameterNames.KEY_ID, kid);
                }
            }

            // Try to load JWK from a single JWK resource or JWK set resource
            JWK jwk = KeyUtils.getJwkKeyFromJwkSet(kid, keyContent);
            if (jwk != null) {
                key = KeyUtils.getPrivateOrSecretSigningKey(jwk, algorithm);
                if (key != null) {
                    // if the algorithm header is not set then use JWK `alg`
                    if (algorithm == null && jwk.getAlgorithm() != null) {
                        headers.put(HeaderParameterNames.ALGORITHM, jwk.getAlgorithm().getName());
                    }
                    // if 'kid' header is not set then use JWK `kid`
                    if (kid == null && jwk.getKeyID() != null) {
                        headers.put(HeaderParameterNames.KEY_ID, jwk.getKeyID());
                    }
                }
            }
        } else {
            configuredPemKey = key;
        }
        return key;
    }

    void removeJti() {
        claims.remove(Claims.jti.name());
    }
}
