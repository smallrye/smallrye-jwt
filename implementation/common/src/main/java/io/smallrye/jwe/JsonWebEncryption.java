package io.smallrye.jwe;

import java.text.ParseException;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;

/**
 * An encrypted token, as given to a decryption key resolver to select a decryption key.
 * <p>
 * The token has been parsed but not decrypted yet, so only its headers are available.
 * It can be decrypted only once, see {@link JweDecrypter#decrypt(JsonWebEncryption)}.
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
     * Parse an encrypted token in its compact serialization form.
     * <p>
     * Only the token format is checked, the token is not decrypted.
     *
     * @param token the token in its compact serialization form
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

        JweHeadersImpl(JWEHeader header) {
            this.header = header;
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
            return header.toJSONObject().get(name);
        }
    }
}
