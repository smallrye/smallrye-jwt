package io.smallrye.jwe;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.XECPublicKey;
import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import com.nimbusds.jose.HeaderParameterNames;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.AESEncrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.PasswordBasedEncrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.Curve;

import io.smallrye.jwt.algorithm.ContentEncryptionAlgorithm;
import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.jwt.algorithm.XDHEncrypter;

/**
 * Encrypts a string as a JSON Web Encryption compact sequence.
 * <p>
 * The encrypted content is an arbitrary string, which can be a JSON document, an already signed
 * JSON Web Token or any other text.
 */
public class JweEncrypter {

    private static final int PBES2_SALT_LENGTH = 16;
    private static final int PBES2_ITERATION_COUNT = 310000;
    private static final int MIN_RSA_KEY_SIZE = 2048;

    private final Key key;
    private final JWEHeader header;

    private JweEncrypter(Key key, JWEHeader header) {
        this.key = key;
        this.header = header;
    }

    /**
     * Create a builder of an encrypter which will use the given key encryption key.
     *
     * @param key the RSA or EC public key or the secret key
     * @return the builder
     */
    public static Builder builder(Key key) {
        return new Builder(key);
    }

    /**
     * Encrypt the content.
     *
     * @param content the content to encrypt
     * @return the JSON Web Encryption compact sequence
     * @throws JweException if the content can not be encrypted
     */
    public String encrypt(String content) throws JweException {
        JWEObject jwe = new JWEObject(header, new Payload(content));
        try {
            jwe.encrypt(createEncrypter(key, header.getAlgorithm().getName()));
        } catch (JOSEException ex) {
            throw new JweException("Failed to encrypt the content: " + ex.getMessage(), ex);
        }
        return jwe.serialize();
    }

    private static JWEEncrypter createEncrypter(Key key, String algorithm) throws JOSEException {
        if (key instanceof RSAPublicKey) {
            return new RSAEncrypter((RSAPublicKey) key);
        } else if (key instanceof ECPublicKey) {
            return new ECDHEncrypter((ECPublicKey) key);
        } else if (key instanceof SecretKey) {
            if (KeyEncryptionAlgorithm.DIR.getAlgorithm().equals(algorithm)) {
                return new DirectEncrypter((SecretKey) key);
            }
            if (algorithm != null && algorithm.startsWith("PBES2")) {
                String password = new String(((SecretKey) key).getEncoded(), StandardCharsets.UTF_8);
                return new PasswordBasedEncrypter(password, PBES2_SALT_LENGTH, PBES2_ITERATION_COUNT);
            }
            return new AESEncrypter((SecretKey) key);
        } else if (key instanceof XECPublicKey) {
            Curve curve = XDHEncrypter.detectCurve((PublicKey) key);
            return new XDHEncrypter((PublicKey) key, curve);
        }
        throw new JOSEException("Unsupported key type for encryption: " + key.getClass().getName());
    }

    /**
     * A builder of a {@link JweEncrypter}.
     */
    public static class Builder {

        private final Key key;
        private KeyEncryptionAlgorithm keyAlgorithm;
        private ContentEncryptionAlgorithm contentAlgorithm = ContentEncryptionAlgorithm.A256GCM;
        private boolean relaxKeyValidation;
        private final Map<String, Object> headers = new LinkedHashMap<>();

        private Builder(Key key) {
            this.key = key;
        }

        /**
         * Set the `alg` key encryption algorithm.
         *
         * @param keyAlgorithm the key encryption algorithm
         * @return this builder
         */
        public Builder keyAlgorithm(KeyEncryptionAlgorithm keyAlgorithm) {
            this.keyAlgorithm = keyAlgorithm;
            return this;
        }

        /**
         * Set the `enc` content encryption algorithm, `A256GCM` by default.
         *
         * @param contentAlgorithm the content encryption algorithm
         * @return this builder
         */
        public Builder contentAlgorithm(ContentEncryptionAlgorithm contentAlgorithm) {
            this.contentAlgorithm = contentAlgorithm;
            return this;
        }

        /**
         * Accept an RSA public key which is shorter than 2048 bits, `false` by default.
         * <p>
         * Note that relaxing the key size validation is not possible for the symmetric key encryption
         * algorithms such as `A256KW` or `A256GCMKW`.
         *
         * @param relaxKeyValidation true if a weak RSA public key is accepted
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
         * Set a JSON Web Encryption header.
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
         * Set the JSON Web Encryption headers.
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
         * Build the encrypter.
         *
         * @return the encrypter
         * @throws JweException if the key or the key encryption algorithm is not set
         */
        public JweEncrypter build() throws JweException {
            if (key == null) {
                throw new JweException("Key encryption key is not set");
            }
            if (keyAlgorithm == null) {
                throw new JweException("Key encryption algorithm is not set");
            }

            // Nimbus RSAEncrypter accepts a public key of any size
            if (key instanceof RSAPublicKey && !relaxKeyValidation) {
                int keySize = ((RSAPublicKey) key).getModulus().bitLength();
                if (keySize < MIN_RSA_KEY_SIZE) {
                    throw new JweException("An RSA key of size " + MIN_RSA_KEY_SIZE + " bits or larger MUST be used"
                            + ", given key was only " + keySize + " bits");
                }
            }

            Map<String, Object> headerMap = new LinkedHashMap<>(headers);
            // the algorithms are set with `keyAlgorithm` and `contentAlgorithm`
            headerMap.put(HeaderParameterNames.ALGORITHM, keyAlgorithm.getAlgorithm());
            headerMap.put(HeaderParameterNames.ENCRYPTION_ALGORITHM, contentAlgorithm.getAlgorithm());

            try {
                return new JweEncrypter(key, JWEHeader.parse(headerMap));
            } catch (ParseException ex) {
                throw new JweException(ex.getMessage(), ex);
            }
        }
    }
}
