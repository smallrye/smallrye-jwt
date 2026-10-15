package io.smallrye.jwe;

import java.text.ParseException;
import java.util.Map;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;

/**
 * Encrypted JWT token representation.
 * <p>
 * The token has been parsed but not decrypted yet, so only its headers are available.
 */
public class JsonWebEncryption {

    private final JWEObject jweObject;
    private final String serialized;
    private final JweHeaders headers;

    private JsonWebEncryption(JWEObject jweObject, String serialized) {
        this.jweObject = jweObject;
        this.serialized = serialized;
        this.headers = new JweHeadersImpl(jweObject.getHeader());
    }

    /**
     * Parse encrypted JWE token sequence.
     *
     * @param token the encrypted JWE token sequence
     * @return the encrypted token
     * @throws JweException if the token is not a well formed encrypted token
     */
    public static JsonWebEncryption parse(String token) throws JweException {
        try {
            return new JsonWebEncryption(JWEObject.parse(token), token);
        } catch (ParseException ex) {
            throw new JweException("Invalid JSON Web Encryption sequence: " + ex.getMessage(), ex);
        }
    }

    /**
     * The token JOSE headers.
     */
    public JweHeaders headers() {
        return headers;
    }

    /**
     * The token in its compact serialization form.
     */
    public String serialized() {
        return serialized;
    }

    JWEObject jweObject() {
        return jweObject;
    }

    private static class JweHeadersImpl implements JweHeaders {

        private final JWEHeader header;
        private final Map<String, Object> headerMap;

        JweHeadersImpl(JWEHeader header) {
            this.header = header;
            this.headerMap = header.toJSONObject();
        }

        @Override
        public String keyId() {
            return header.getKeyID();
        }

        @Override
        public String algorithm() {
            return header.getAlgorithm().getName();
        }

        @Override
        public String encryptionAlgorithm() {
            return header.getEncryptionMethod() != null ? header.getEncryptionMethod().getName() : null;
        }

        @Override
        public String type() {
            JOSEObjectType type = header.getType();
            return type != null ? type.toString() : null;
        }

        @Override
        public String contentType() {
            return header.getContentType();
        }

        @Override
        public Object header(String name) {
            return headerMap.get(name);
        }
    }
}
