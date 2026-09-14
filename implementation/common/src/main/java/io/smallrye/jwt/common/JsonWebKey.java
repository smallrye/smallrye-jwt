package io.smallrye.jwt.common;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;

import io.smallrye.jwt.algorithm.EdDSASigner;
import io.smallrye.jwt.algorithm.EdDSAVerifier;

/**
 * A JSON Web Key backed by a Map of its properties.
 */
public class JsonWebKey {

    private static final String SECRET_KEY_ALGORITHM = "AES";

    private final Map<String, Object> properties;
    private final JWK jwk;

    JsonWebKey(JWK jwk) {
        this.jwk = jwk;
        this.properties = new LinkedHashMap<>(jwk.toJSONObject());
    }

    /**
     * Create a JSON Web Key representing the given public key.
     *
     * @param key the RSA, EC or EdDSA public key
     * @return the JSON Web Key
     * @throws JsonWebKeyException if the key can not be converted to a JSON Web Key
     */
    public static JsonWebKey jwk(PublicKey key) throws JsonWebKeyException {
        return new JsonWebKey(toJwk(key));
    }

    /**
     * Create a JSON Web Key from its properties.
     *
     * @param properties the JSON Web Key properties
     * @return the JSON Web Key
     * @throws JsonWebKeyException if the properties do not represent a valid JSON Web Key
     */
    public static JsonWebKey jwk(Map<String, Object> properties) throws JsonWebKeyException {
        try {
            return new JsonWebKey(JWK.parse(properties));
        } catch (ParseException ex) {
            throw new JsonWebKeyException("Invalid JSON Web Key: " + ex.getMessage(), ex);
        }
    }

    /**
     * Parse a JSON Web Key.
     *
     * @param content the JSON Web Key content
     * @return the JSON Web Key
     * @throws JsonWebKeyException if the content is not a valid JSON Web Key
     */
    public static JsonWebKey parse(String content) throws JsonWebKeyException {
        try {
            return new JsonWebKey(JWK.parse(content));
        } catch (ParseException ex) {
            throw new JsonWebKeyException("Invalid JSON Web Key: " + ex.getMessage(), ex);
        }
    }

    /**
     * The JSON Web Key properties.
     *
     * @return an unmodifiable map of the JSON Web Key properties
     */
    public Map<String, Object> asMap() {
        return Collections.unmodifiableMap(properties);
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
     * @return the key type, or null if it is not set
     */
    public String keyType() {
        return jwk.getKeyType() != null ? jwk.getKeyType().getValue() : null;
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
        List<X509Certificate> chain = x509CertificateChain();
        return chain != null ? X509CertUtils.computeSHA1Thumbprint(chain.get(0)).toString() : null;
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
        List<X509Certificate> chain = x509CertificateChain();
        return chain != null ? X509CertUtils.computeSHA256Thumbprint(chain.get(0)).toString() : null;
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
    public List<X509Certificate> x509CertificateChain() {
        List<X509Certificate> chain = jwk.getParsedX509CertChain();
        return chain == null || chain.isEmpty() ? null : chain;
    }

    /**
     * The public key this JSON Web Key represents.
     *
     * @return the public key, or null if this JSON Web Key does not represent an asymmetric key
     * @throws JsonWebKeyException if the public key can not be created
     */
    public PublicKey publicKey() throws JsonWebKeyException {
        try {
            if (jwk instanceof OctetKeyPair) {
                // Nimbus does not support exporting an OKP as a java.security.PublicKey
                return EdDSAVerifier.toPublicKey((OctetKeyPair) jwk);
            }
            if (jwk instanceof AsymmetricJWK) {
                return ((AsymmetricJWK) jwk).toPublicKey();
            }
            return null;
        } catch (JOSEException ex) {
            throw new JsonWebKeyException("Failed to create a public key from the JSON Web Key: " + ex.getMessage(), ex);
        }
    }

    /**
     * The private key this JSON Web Key represents.
     *
     * @return the private key, or null if this JSON Web Key does not represent an asymmetric private key
     * @throws JsonWebKeyException if the private key can not be created
     */
    public PrivateKey privateKey() throws JsonWebKeyException {
        try {
            if (jwk instanceof OctetKeyPair) {
                // Nimbus does not support exporting an OKP as a java.security.PrivateKey
                return EdDSASigner.toPrivateKey((OctetKeyPair) jwk);
            }
            if (jwk instanceof AsymmetricJWK) {
                return ((AsymmetricJWK) jwk).toPrivateKey();
            }
            return null;
        } catch (JOSEException ex) {
            throw new JsonWebKeyException("Failed to create a private key from the JSON Web Key: " + ex.getMessage(), ex);
        }
    }

    /**
     * The secret key this JSON Web Key represents.
     *
     * @return the secret key, or null if this JSON Web Key does not represent a symmetric key
     */
    public SecretKey secretKey() {
        if (jwk instanceof OctetSequenceKey) {
            return ((OctetSequenceKey) jwk).toSecretKey(SECRET_KEY_ALGORITHM);
        }
        return null;
    }

    private static JWK toJwk(PublicKey key) throws JsonWebKeyException {
        if (key instanceof RSAPublicKey) {
            return new RSAKey.Builder((RSAPublicKey) key).build();
        } else if (key instanceof ECPublicKey) {
            return ecPublicKeyToJwk((ECPublicKey) key);
        } else if (key instanceof EdECPublicKey) {
            return edEcPublicKeyToJwk(key);
        } else {
            throw new JsonWebKeyException("Unsupported public key algorithm: " + key.getAlgorithm());
        }
    }

    private static JWK ecPublicKeyToJwk(ECPublicKey ecKey) {
        Curve curve = Curve.forECParameterSpec(ecKey.getParams());
        return new ECKey.Builder(curve, ecKey).build();
    }

    private static JWK edEcPublicKeyToJwk(PublicKey key) throws JsonWebKeyException {
        String alg = key.getAlgorithm();
        Curve curve;
        if ("Ed25519".equals(alg)) {
            curve = Curve.Ed25519;
        } else if ("Ed448".equals(alg)) {
            curve = Curve.Ed448;
        } else if ("EdDSA".equals(alg)) {
            // Detect curve from encoded key length: Ed25519=44, Ed448=69
            curve = key.getEncoded().length <= 50 ? Curve.Ed25519 : Curve.Ed448;
        } else {
            throw new JsonWebKeyException("Unsupported EdDSA algorithm: " + alg);
        }

        // The X.509 SubjectPublicKeyInfo for EdDSA wraps the raw public key in a
        // BIT STRING inside a SEQUENCE with an AlgorithmIdentifier.
        // The raw key bytes are after the ASN.1 header.
        // Rather than parsing ASN.1, use the key's encoded bytes and strip the header.
        byte[] encoded = key.getEncoded();
        // The last N bytes are the raw public key (32 for Ed25519, 57 for Ed448)
        int rawLen = curve == Curve.Ed25519 ? 32 : 57;
        if (encoded.length < rawLen) {
            throw new JsonWebKeyException("Encoded key too short");
        }
        byte[] rawBytes = new byte[rawLen];
        System.arraycopy(encoded, encoded.length - rawLen, rawBytes, 0, rawLen);

        return new OctetKeyPair.Builder(curve, Base64URL.encode(rawBytes)).build();
    }
}
