package io.smallrye.jws;

import java.security.Key;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import javax.crypto.SecretKey;

import com.nimbusds.jose.HeaderParameterNames;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSSignerOption;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.opts.AllowWeakRSAKey;
import com.nimbusds.jose.jwk.Curve;

import io.smallrye.jwt.algorithm.EdDSASigner;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;

/**
 * Signs a string as a JSON Web Signature compact sequence.
 * <p>
 * The signed content is an arbitrary string such as encoded JWT claims or any other text.
 */
public class JwsSigner {

    private final Key key;
    private final JWSHeader header;
    private final boolean relaxKeyValidation;

    private JwsSigner(Key key, JWSHeader header, boolean relaxKeyValidation) {
        this.key = key;
        this.header = header;
        this.relaxKeyValidation = relaxKeyValidation;
    }

    /**
     * Create a builder of a signer which will use the given signing key.
     *
     * @param key the RSA, EC or EdDSA private key or the secret key
     * @return the builder
     */
    public static Builder builder(Key key) {
        return new Builder(key);
    }

    /**
     * Sign the content.
     *
     * @param content the content to sign
     * @return the JSON Web Signature compact sequence
     * @throws JwsException if the content can not be signed
     */
    public String sign(String content) throws JwsException {
        JWSObject jws = new JWSObject(header, new Payload(content));
        try {
            jws.sign(createSigner(key, header.getAlgorithm(), relaxKeyValidation));
        } catch (JOSEException | IllegalArgumentException ex) {
            throw new JwsException(ex.getMessage(), ex);
        }
        return jws.serialize();
    }

    private static JWSSigner createSigner(Key key, JWSAlgorithm alg, boolean relaxKeyValidation) throws JOSEException {
        // Opaque RSA and EC private keys, for example, PKCS#11 keys, do not implement RSAPrivateKey or ECPrivateKey
        if (key instanceof RSAPrivateKey || (key instanceof PrivateKey && "RSA".equalsIgnoreCase(key.getAlgorithm()))) {
            // Nimbus RSASSASigner rejects the keys shorter than 2048 bits unless `AllowWeakRSAKey` is set
            Set<JWSSignerOption> opts = relaxKeyValidation
                    ? Collections.<JWSSignerOption> singleton(AllowWeakRSAKey.getInstance())
                    : Collections.<JWSSignerOption> emptySet();
            return new RSASSASigner((PrivateKey) key, opts);
        } else if (key instanceof ECPrivateKey) {
            return new ECDSASigner((ECPrivateKey) key);
        } else if (key instanceof PrivateKey && "EC".equalsIgnoreCase(key.getAlgorithm())) {
            // The curve is derived from the ES* algorithm
            Set<Curve> curves = Curve.forJWSAlgorithm(alg);
            if (curves == null) {
                throw new JOSEException("Unsupported algorithm for an EC private key: " + alg);
            }
            return new ECDSASigner((PrivateKey) key, curves.iterator().next());
        } else if (key instanceof SecretKey) {
            return new MACSigner((SecretKey) key);
        } else if (key instanceof EdECPrivateKey || (key instanceof PrivateKey && isEdDsaAlgorithm(key.getAlgorithm()))) {
            // Opaque EdDSA private keys, for example, PKCS#11 keys, do not implement EdECPrivateKey
            return new EdDSASigner((PrivateKey) key);
        }
        throw new JOSEException("Unsupported key type for signing: " + key.getClass().getName());
    }

    private static boolean isEdDsaAlgorithm(String algorithm) {
        return "EdDSA".equalsIgnoreCase(algorithm) || "Ed25519".equalsIgnoreCase(algorithm)
                || "Ed448".equalsIgnoreCase(algorithm);
    }

    /**
     * A builder of a {@link JwsSigner}.
     */
    public static class Builder {

        private final Key key;
        private SignatureAlgorithm algorithm;
        private boolean relaxKeyValidation;
        private final Map<String, Object> headers = new LinkedHashMap<>();

        private Builder(Key key) {
            this.key = key;
        }

        /**
         * Set the `alg` signature algorithm.
         *
         * @param algorithm the signature algorithm
         * @return this builder
         */
        public Builder algorithm(SignatureAlgorithm algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        /**
         * Accept an RSA private key which is shorter than 2048 bits, `false` by default.
         * <p>
         * Note that relaxing the key size validation is not possible for the HMAC algorithms.
         *
         * @param relaxKeyValidation true if a weak RSA private key is accepted
         * @return this builder
         */
        public Builder relaxKeyValidation(boolean relaxKeyValidation) {
            this.relaxKeyValidation = relaxKeyValidation;
            return this;
        }

        /**
         * Set the `kid` key identifier.
         *
         * @param keyId the key identifier
         * @return this builder
         */
        public Builder keyId(String keyId) {
            return header(HeaderParameterNames.KEY_ID, keyId);
        }

        /**
         * Set the `cty` content type.
         *
         * @param contentType the content type
         * @return this builder
         */
        public Builder contentType(String contentType) {
            return header(HeaderParameterNames.CONTENT_TYPE, contentType);
        }

        /**
         * Set the `typ` type.
         *
         * @param type the type
         * @return this builder
         */
        public Builder type(String type) {
            return header(HeaderParameterNames.TYPE, type);
        }

        /**
         * Set a JSON Web Signature header.
         *
         * @param name the header name
         * @param value the header value
         * @return this builder
         */
        public Builder header(String name, Object value) {
            headers.put(name, value);
            return this;
        }

        /**
         * Set the JSON Web Signature headers.
         *
         * @param headers the headers
         * @return this builder
         */
        public Builder headers(Map<String, Object> headers) {
            for (Map.Entry<String, Object> entry : headers.entrySet()) {
                header(entry.getKey(), entry.getValue());
            }
            return this;
        }

        /**
         * Build the signer.
         *
         * @return the signer
         * @throws JwsException if the key or the signature algorithm is not set
         */
        public JwsSigner build() throws JwsException {
            if (key == null) {
                throw new JwsException("Signing key is not set");
            }
            if (algorithm == null) {
                throw new JwsException("Signature algorithm is not set");
            }

            Map<String, Object> headerMap = new LinkedHashMap<>(headers);
            // the algorithm is set with `algorithm`
            headerMap.put(HeaderParameterNames.ALGORITHM, algorithm.getAlgorithm());

            try {
                return new JwsSigner(key, JWSHeader.parse(headerMap), relaxKeyValidation);
            } catch (ParseException ex) {
                throw new JwsException(ex.getMessage(), ex);
            }
        }
    }
}
