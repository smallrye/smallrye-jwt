package io.smallrye.jwk;

import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.XECPublicKey;
import java.text.ParseException;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;

import io.smallrye.jwt.util.KeyUtils;

/**
 * A JSON Web Key.
 * <p>
 * A JSON Web Key is either an {@linkplain AsymmetricJsonWebKey asymmetric key}, which is one of
 * {@link RsaJsonWebKey}, {@link EcJsonWebKey} and {@link OctetKeyPairJsonWebKey}, or a symmetric {@link SecretJsonWebKey}.
 */
public abstract class JsonWebKey {

    /**
     * Controls which properties are included when a JSON Web Key is output with {@link #asMap(OutputLevel)}
     * or {@link #asJsonString(OutputLevel)}.
     */
    public enum OutputLevel {
        /**
         * The public properties only: the private key material of an asymmetric key and the `k` secret value
         * of a symmetric key are omitted.
         */
        PUBLIC_ONLY,
        /**
         * All the properties, including the private key material of an asymmetric key and the `k` secret value
         * of a symmetric key.
         */
        INCLUDE_PRIVATE
    }

    private final Map<String, Object> properties;
    private final JWK jwk;

    JsonWebKey(JWK jwk) {
        this.jwk = jwk;
        this.properties = new LinkedHashMap<>(jwk.toJSONObject());
    }

    /**
     * Create a JSON Web Key representing the given public key.
     *
     * @param key the RSA, EC, EdDSA or XDH public key
     * @return the JSON Web Key
     * @throws JsonWebKeyException if the key can not be converted to a JSON Web Key
     */
    public static AsymmetricJsonWebKey jwk(PublicKey key) throws JsonWebKeyException {
        if (key instanceof RSAPublicKey) {
            return RsaJsonWebKey.builder((RSAPublicKey) key).build();
        } else if (key instanceof ECPublicKey) {
            return EcJsonWebKey.builder((ECPublicKey) key).build();
        } else if (key instanceof EdECPublicKey || key instanceof XECPublicKey) {
            return OctetKeyPairJsonWebKey.builder(key).build();
        } else {
            throw new JsonWebKeyException("Unsupported public key algorithm: " + key.getAlgorithm());
        }
    }

    /**
     * Create a JSON Web Key from its properties.
     *
     * @param properties the JSON Web Key properties
     * @return the JSON Web Key
     * @throws JsonWebKeyException if the properties do not represent a supported JSON Web Key
     */
    public static JsonWebKey jwk(Map<String, Object> properties) throws JsonWebKeyException {
        try {
            return of(JWK.parse(properties));
        } catch (ParseException ex) {
            throw new JsonWebKeyException("Invalid JSON Web Key: " + ex.getMessage(), ex);
        }
    }

    /**
     * Parse a JSON Web Key.
     *
     * @param content the JSON Web Key content
     * @return the JSON Web Key
     * @throws JsonWebKeyException if the content is not a supported JSON Web Key
     */
    public static JsonWebKey parse(String content) throws JsonWebKeyException {
        try {
            return of(JWK.parse(content));
        } catch (ParseException ex) {
            throw new JsonWebKeyException("Invalid JSON Web Key: " + ex.getMessage(), ex);
        }
    }

    static JsonWebKey of(JWK jwk) throws JsonWebKeyException {
        if (jwk instanceof RSAKey) {
            return new RsaJsonWebKey((RSAKey) jwk);
        } else if (jwk instanceof ECKey) {
            return new EcJsonWebKey((ECKey) jwk);
        } else if (jwk instanceof OctetKeyPair) {
            return new OctetKeyPairJsonWebKey((OctetKeyPair) jwk);
        } else if (jwk instanceof OctetSequenceKey) {
            return new SecretJsonWebKey((OctetSequenceKey) jwk);
        } else {
            throw new JsonWebKeyException("Unsupported JSON Web Key type: " + jwk.getKeyType());
        }
    }

    JWK jwk() {
        return jwk;
    }

    /**
     * The JSON Web Key properties.
     * <p>
     * The private key material of an asymmetric key is omitted, the `k` secret value of a symmetric key
     * is included. Use {@link #asMap(OutputLevel)} to control it.
     *
     * @return an unmodifiable map of the JSON Web Key properties
     */
    public Map<String, Object> asMap() {
        return asMap(jwk instanceof OctetSequenceKey ? OutputLevel.INCLUDE_PRIVATE : OutputLevel.PUBLIC_ONLY);
    }

    /**
     * The JSON Web Key properties.
     *
     * @param outputLevel controls whether the private or secret key material is included
     * @return an unmodifiable map of the JSON Web Key properties
     */
    public Map<String, Object> asMap(OutputLevel outputLevel) {
        if (outputLevel == OutputLevel.INCLUDE_PRIVATE) {
            return Collections.unmodifiableMap(properties);
        }
        Map<String, Object> publicProperties;
        if (jwk instanceof OctetSequenceKey) {
            // a symmetric key has no public form, drop the secret value only
            publicProperties = new LinkedHashMap<>(properties);
            publicProperties.remove("k");
        } else {
            publicProperties = jwk.toPublicJWK().toJSONObject();
        }
        return Collections.unmodifiableMap(publicProperties);
    }

    /**
     * The JSON Web Key as a JSON string.
     * <p>
     * The private key material of an asymmetric key is omitted, the `k` secret value of a symmetric key
     * is included. Use {@link #asJsonString(OutputLevel)} to control it.
     *
     * @return the JSON representation of this JSON Web Key
     */
    public String asJsonString() {
        return asJsonString(jwk instanceof OctetSequenceKey ? OutputLevel.INCLUDE_PRIVATE : OutputLevel.PUBLIC_ONLY);
    }

    /**
     * The JSON Web Key as a JSON string.
     *
     * @param outputLevel controls whether the private or secret key material is included
     * @return the JSON representation of this JSON Web Key
     */
    public String asJsonString(OutputLevel outputLevel) {
        return JSONObjectUtils.toJSONString(asMap(outputLevel));
    }

    /**
     * The `kid` key identifier.
     *
     * @return the key identifier, or null if it is not set
     */
    public String keyId() {
        return jwk.getKeyID();
    }

    /**
     * The `kty` key type, for example, `RSA`, `EC`, `OKP` or `oct`.
     *
     * @return the key type
     */
    public String keyType() {
        return jwk.getKeyType().getValue();
    }

    /**
     * The `alg` algorithm this key is intended to be used with.
     *
     * @return the algorithm, or null if it is not set
     */
    public String algorithm() {
        return jwk.getAlgorithm() != null ? jwk.getAlgorithm().getName() : null;
    }

    /**
     * The `use` public key use, for example, `sig` or `enc`.
     *
     * @return the public key use, or null if it is not set
     */
    public String keyUse() {
        return jwk.getKeyUse() != null ? jwk.getKeyUse().getValue() : null;
    }

    /**
     * The `key_ops` operations this key is intended to be used for, for example, `sign` or `encrypt`.
     *
     * @return the key operations, or null if they are not set, in which case the key use is not restricted
     */
    public Set<String> keyOperations() {
        Set<KeyOperation> keyOps = jwk.getKeyOperations();
        if (keyOps == null) {
            return null;
        }
        return keyOps.stream().map(KeyOperation::identifier).collect(Collectors.toSet());
    }

    /**
     * The `x5t` SHA-1 thumbprint of the X.509 certificate this key corresponds to.
     * <p>
     * If the thumbprint is not set but the certificate chain is, then the thumbprint is calculated
     * from the leaf certificate.
     *
     * @return the base64url encoded SHA-1 thumbprint, or null if it is neither set nor can be calculated
     */
    public String x509CertificateThumbprint() {
        Base64URL x5t = jwk.getX509CertThumbprint();
        if (x5t != null) {
            return x5t.toString();
        }
        return computeChainThumbprint(false);
    }

    /**
     * The `x5t#S256` SHA-256 thumbprint of the X.509 certificate this key corresponds to.
     * <p>
     * If the thumbprint is not set but the certificate chain is, then the thumbprint is calculated
     * from the leaf certificate.
     *
     * @return the base64url encoded SHA-256 thumbprint, or null if it is neither set nor can be calculated
     */
    public String x509CertificateS256Thumbprint() {
        Base64URL x5tS256 = jwk.getX509CertSHA256Thumbprint();
        if (x5tS256 != null) {
            return x5tS256.toString();
        }
        return computeChainThumbprint(true);
    }

    /**
     * Compute the RFC 7638 SHA-256 thumbprint of this key.
     *
     * @return the base64url encoded thumbprint
     * @throws JsonWebKeyException if the thumbprint can not be computed
     */
    public String computeThumbprint() throws JsonWebKeyException {
        try {
            return jwk.computeThumbprint().toString();
        } catch (JOSEException ex) {
            throw new JsonWebKeyException("Failed to compute the JSON Web Key thumbprint: " + ex.getMessage(), ex);
        }
    }

    /**
     * The certificates of the {@code x5c} property, in the order they appear in the JSON Web Key.
     *
     * @return the certificate chain, with the certificate matching this key first
     */
    private String computeChainThumbprint(boolean sha256) {
        List<X509Certificate> chain = x509CertificateChain();
        if (chain == null) {
            return null;
        }
        try {
            return sha256 ? KeyUtils.getCertificateSha256Thumbprint(chain.get(0))
                    : KeyUtils.getCertificateThumbprint(chain.get(0));
        } catch (CertificateEncodingException ex) {
            return null;
        }
    }

    public List<X509Certificate> x509CertificateChain() {
        List<X509Certificate> chain = jwk.getParsedX509CertChain();
        return chain == null || chain.isEmpty() ? null : chain;
    }

    /**
     * A builder of a JSON Web Key.
     * <p>
     * The properties such as `kid`, `use` and `alg` are common to all the JSON Web Key types,
     * the fluent methods setting them are provided by the concrete builders.
     */
    public abstract static class Builder {

        private final Map<String, Object> properties = new HashMap<>();

        Builder() {
        }

        /**
         * Build the JSON Web Key.
         *
         * @return the JSON Web Key
         * @throws JsonWebKeyException if the JSON Web Key can not be created
         */
        public abstract JsonWebKey build() throws JsonWebKeyException;

        void putProperty(String name, String value) {
            properties.put(name, value);
        }

        /**
         * The key material this builder was created with, either generated or converted from an existing key.
         */
        abstract JWK keyJwk() throws JsonWebKeyException;

        JWK buildJwk() throws JsonWebKeyException {
            Map<String, Object> allProperties = keyJwk().toJSONObject();
            allProperties.putAll(properties);
            try {
                return JWK.parse(allProperties);
            } catch (ParseException ex) {
                throw new JsonWebKeyException("Invalid JSON Web Key: " + ex.getMessage(), ex);
            }
        }
    }
}
