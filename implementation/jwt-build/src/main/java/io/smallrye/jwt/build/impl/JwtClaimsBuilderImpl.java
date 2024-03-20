package io.smallrye.jwt.build.impl;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import jakarta.json.JsonNumber;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;

import org.eclipse.microprofile.jwt.Claims;
import org.jose4j.base64url.Base64;
import org.jose4j.jwk.JsonWebKey.OutputControlLevel;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.keys.X509Util;
import org.jose4j.lang.JoseException;

import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.build.JwtClaimsBuilder;
import io.smallrye.jwt.build.JwtEncryptionBuilder;
import io.smallrye.jwt.build.JwtSignatureBuilder;
import io.smallrye.jwt.build.JwtSignatureException;

/**
 * Default JWT Claims Builder
 *
 */
class JwtClaimsBuilderImpl extends JwtSignatureImpl implements JwtClaimsBuilder, JwtSignatureBuilder {

    private static final String SCOPE_CLAIM = "scope";
    private static final StringVerifier STRING_VERIFIER = new StringVerifier();
    private static final InstantVerifier INSTANT_VERIFIER = new InstantVerifier();
    private static final StringCollectionVerifier STRING_COLLECTION_VERIFIER = new StringCollectionVerifier();
    private static final Map<String, ClaimTypeVerifier> REGISTERED_CLAIM_VERIFIERS;
    static {
        REGISTERED_CLAIM_VERIFIERS = new HashMap<>();
        REGISTERED_CLAIM_VERIFIERS.put(Claims.sub.name(), STRING_VERIFIER);
        REGISTERED_CLAIM_VERIFIERS.put(Claims.iss.name(), STRING_VERIFIER);
        REGISTERED_CLAIM_VERIFIERS.put(Claims.jti.name(), STRING_VERIFIER);
        REGISTERED_CLAIM_VERIFIERS.put(Claims.upn.name(), STRING_VERIFIER);
        REGISTERED_CLAIM_VERIFIERS.put(Claims.preferred_username.name(), STRING_VERIFIER);
        REGISTERED_CLAIM_VERIFIERS.put(Claims.iat.name(), INSTANT_VERIFIER);
        REGISTERED_CLAIM_VERIFIERS.put(Claims.auth_time.name(), INSTANT_VERIFIER);
        REGISTERED_CLAIM_VERIFIERS.put(Claims.exp.name(), INSTANT_VERIFIER);
        REGISTERED_CLAIM_VERIFIERS.put(Claims.aud.name(), STRING_COLLECTION_VERIFIER);
        REGISTERED_CLAIM_VERIFIERS.put(Claims.groups.name(), STRING_COLLECTION_VERIFIER);
    }

    JwtClaimsBuilderImpl() {

    }

    JwtClaimsBuilderImpl(String jsonLocation) {
        super(parseJsonToClaims(jsonLocation));
    }

    JwtClaimsBuilderImpl(Map<String, Object> claimsMap) {
        super(fromMapToJwtClaims(claimsMap));
    }

    private static JwtClaims fromMapToJwtClaims(Map<String, Object> claimsMap) {
        JwtClaims claims = new JwtClaims();
        @SuppressWarnings("unchecked")
        Map<String, Object> newMap = (Map<String, Object>) prepareValue(claimsMap);
        for (Map.Entry<String, Object> entry : newMap.entrySet()) {
            claims.setClaim(entry.getKey(), entry.getValue());
        }
        return claims;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsBuilder claim(String name, Object value) {
        claims.setClaim(name, verifyValueType(name, prepareValue(value)));
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsBuilder issuer(String issuer) {
        claims.setIssuer(issuer);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsBuilder audience(String audience) {
        return audience(Collections.singleton(audience));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsBuilder audience(Set<String> audiences) {
        claims.setAudience(audiences.stream().collect(Collectors.toList()));
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsBuilder subject(String subject) {
        claims.setSubject(subject);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsBuilder upn(String upn) {
        claims.setClaim(Claims.upn.name(), upn);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsBuilder preferredUserName(String preferredUserName) {
        claims.setClaim(Claims.preferred_username.name(), preferredUserName);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsBuilder issuedAt(long issuedAt) {
        claims.setIssuedAt(NumericDate.fromSeconds(issuedAt));
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsBuilder expiresAt(long expiresAt) {
        claims.setExpirationTime(NumericDate.fromSeconds(expiresAt));
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsBuilder expiresIn(long expiresIn) {
        tokenLifespan = expiresIn;
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsBuilder groups(Set<String> groups) {
        claims.setClaim(Claims.groups.name(), groups.stream().collect(Collectors.toList()));
        return this;
    }

    @Override
    public JwtClaimsBuilder scope(Set<String> scopes) {
        claims.setClaim(SCOPE_CLAIM, scopes.stream().collect(Collectors.joining(" ")));
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtSignatureBuilder jws() {
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtSignatureBuilder header(String name, Object value) {
        if ("alg".equals(name)) {
            return algorithm(toSignatureAlgorithm((String) value));
        } else {
            headers.put(name, value);
            return this;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtSignatureBuilder algorithm(SignatureAlgorithm algorithm) {
        headers.put(HeaderParameterNames.ALGORITHM, algorithm.name());
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtSignatureBuilder keyId(String keyId) {
        headers.put(HeaderParameterNames.KEY_ID, keyId);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtSignatureBuilder thumbprint(X509Certificate cert) {
        headers.put(HeaderParameterNames.X509_CERTIFICATE_THUMBPRINT, X509Util.x5t(cert));
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtSignatureBuilder thumbprintS256(X509Certificate cert) {
        headers.put(HeaderParameterNames.X509_CERTIFICATE_SHA256_THUMBPRINT, X509Util.x5tS256(cert));
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtSignatureBuilder chain(List<X509Certificate> chain) {
        List<String> base64EncodedCerts = new ArrayList<>(chain.size());
        try {
            for (X509Certificate cert : chain) {
                base64EncodedCerts.add(Base64.encode(cert.getEncoded()));
            }
            headers.put(HeaderParameterNames.X509_CERTIFICATE_CHAIN, base64EncodedCerts);
        } catch (CertificateEncodingException ex) {
            throw ImplMessages.msg.signatureException(ex);
        }
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtSignatureBuilder jwk(PublicKey key) {
        headers.put(HeaderParameterNames.JWK, convertPublicKeyToJwk(key));
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtEncryptionBuilder innerSign(PrivateKey signingKey) throws JwtSignatureException {
        return super.innerSign(signingKey);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtEncryptionBuilder innerSign(SecretKey signingKey) throws JwtSignatureException {
        return super.innerSign(signingKey);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtEncryptionBuilder innerSign() throws JwtSignatureException {
        return super.innerSign();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtEncryptionBuilder jwe() {
        JwtBuildUtils.setDefaultJwtClaims(claims, tokenLifespan);
        try {
            return new JwtEncryptionImpl(claims.toJson());
        } finally {
            removeJti();
        }
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    private static Object prepareValue(Object value) {
        if (value instanceof Collection) {
            return ((Collection) value).stream().map(o -> prepareValue(o)).collect(Collectors.toList());
        }

        if (value instanceof Map) {
            Map<String, Object> map = (Map) value;
            Map<String, Object> newMap = new LinkedHashMap<>();
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                newMap.put(entry.getKey(), prepareValue(entry.getValue()));
            }
            return newMap;
        }

        if (value instanceof JsonValue) {
            return convertJsonValue((JsonValue) value);
        }

        if (value instanceof Number || value instanceof Boolean) {
            return value;
        }

        if (value instanceof Instant) {
            return ((Instant) value).getEpochSecond();
        }

        if (value instanceof PublicKey) {
            return convertPublicKeyToJwk((PublicKey) value);
        }

        return value.toString();
    }

    private static Object convertJsonValue(JsonValue jsonValue) {
        if (jsonValue instanceof JsonString) {
            String jsonString = jsonValue.toString();
            return jsonString.toString().substring(1, jsonString.length() - 1);
        } else if (jsonValue instanceof JsonNumber) {
            JsonNumber jsonNumber = (JsonNumber) jsonValue;
            if (jsonNumber.isIntegral()) {
                return jsonNumber.longValue();
            } else {
                return jsonNumber.doubleValue();
            }
        } else if (jsonValue == JsonValue.TRUE) {
            return true;
        } else if (jsonValue == JsonValue.FALSE) {
            return false;
        } else {
            return null;
        }
    }

    private static JwtClaims parseJsonToClaims(String jsonLocation) {
        return JwtBuildUtils.parseJwtClaims(jsonLocation);
    }

    private static SignatureAlgorithm toSignatureAlgorithm(String value) {
        try {
            return SignatureAlgorithm.fromAlgorithm(value);
        } catch (Exception ex) {
            throw ImplMessages.msg.unsupportedSignatureAlgorithm(value, ex);
        }
    }

    private static Object verifyValueType(String name, Object value) {
        ClaimTypeVerifier verifier = REGISTERED_CLAIM_VERIFIERS.get(name);
        return verifier == null ? value : verifier.verify(name, value);
    }

    static interface ClaimTypeVerifier {
        // Verify the claim value type
        Object verify(String name, Object value);
    }

    static class StringVerifier implements ClaimTypeVerifier {
        public Object verify(String name, Object value) {
            if (value instanceof String) {
                return value;
            }
            throw new IllegalArgumentException(String.format("'%s' claim value must be String", name));
        }
    }

    static class InstantVerifier implements ClaimTypeVerifier {
        public Object verify(String name, Object value) {
            if (value instanceof Long) {
                return value;
            }
            // If a Number is passed, it must be converted to long
            if (value instanceof Number) {
                return ((Number) value).longValue();
            }
            throw new IllegalArgumentException(String.format("'%s' claim value must be long", name));
        }
    }

    static class StringCollectionVerifier implements ClaimTypeVerifier {
        public Object verify(String name, Object value) {
            if (value instanceof String) {
                return value;
            } else if (value instanceof Collection) {
                Iterator<?> it = ((Collection<?>) value).iterator();
                if (it.hasNext() && it.next() instanceof String) {
                    return value;
                }
            }
            throw new IllegalArgumentException(String.format("'%s' claim value must be String or Collection of Strings", name));
        }
    }

    static Map<String, Object> convertPublicKeyToJwk(PublicKey key) {
        try {
            return PublicJsonWebKey.Factory.newPublicJwk(key).toParams(OutputControlLevel.PUBLIC_ONLY);
        } catch (JoseException ex) {
            throw ImplMessages.msg.signatureException(ex);
        }
    }

    @Override
    public JwtClaimsBuilder remove(String name) {
        claims.unsetClaim(name);
        return this;
    }
}
