package io.smallrye.jwt.auth.principal;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;

import io.smallrye.jwt.auth.JsonWebEncryption;
import io.smallrye.jwt.auth.JweHeaders;

public class JsonWebEncryptionImpl implements JsonWebEncryption {

    private final String token;
    private final JweHeaders headers;

    public JsonWebEncryptionImpl(JWEObject jweObject, String token) {
        this.token = token;
        this.headers = new JweHeadersImpl(jweObject.getHeader());
    }

    @Override
    public JweHeaders headers() {
        return headers;
    }

    @Override
    public String serialized() {
        return token;
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
