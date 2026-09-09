package io.smallrye.jwt.auth.principal;

import java.security.cert.X509Certificate;
import java.util.List;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.X509CertChainUtils;
import com.nimbusds.jwt.SignedJWT;

import io.smallrye.jwt.auth.JsonWebSignature;
import io.smallrye.jwt.auth.JwsHeaders;
import io.smallrye.jwt.auth.UnresolvableKeyException;

public class JsonWebSignatureImpl implements JsonWebSignature {

    private final SignedJWT signedJWT;
    private final String token;
    private final JwsHeaders headers;

    public JsonWebSignatureImpl(SignedJWT signedJWT, String token) {
        this.signedJWT = signedJWT;
        this.token = token;
        this.headers = new JwsHeadersImpl(signedJWT.getHeader());
    }

    @Override
    public JwsHeaders headers() {
        return headers;
    }

    @Override
    public String unverifiedPayload() {
        return signedJWT.getPayload().toString();
    }

    @Override
    public String serialized() {
        return token;
    }

    private static class JwsHeadersImpl implements JwsHeaders {

        private final JWSHeader header;

        JwsHeadersImpl(JWSHeader header) {
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
        public String type() {
            JOSEObjectType type = header.getType();
            return type != null ? type.toString() : null;
        }

        @Override
        public String contentType() {
            return header.getContentType();
        }

        @Override
        public String x509CertificateThumbprint() {
            return header.getX509CertThumbprint() != null ? header.getX509CertThumbprint().toString() : null;
        }

        @Override
        public String x509CertificateSha256Thumbprint() {
            return header.getX509CertSHA256Thumbprint() != null
                    ? header.getX509CertSHA256Thumbprint().toString()
                    : null;
        }

        @Override
        public List<X509Certificate> x509CertificateChain() throws UnresolvableKeyException {
            List<Base64> chain = header.getX509CertChain();
            if (chain == null) {
                return null;
            }
            try {
                return X509CertChainUtils.parse(chain);
            } catch (java.text.ParseException e) {
                throw new UnresolvableKeyException("Invalid certificate chain", e);
            }
        }

        @Override
        public Object header(String name) {
            return header.toJSONObject().get(name);
        }
    }
}
