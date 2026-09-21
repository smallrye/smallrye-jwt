package io.smallrye.jws;

import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.List;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.X509CertChainUtils;
import com.nimbusds.jwt.SignedJWT;

/**
 * A signed token, as given to a verification key resolver to select a verification key.
 * <p>
 * The token has been parsed but its signature has not been verified yet, so neither the headers nor
 * the payload can be trusted, see {@link JwsVerifier#verify(JsonWebSignature)}.
 */
public class JsonWebSignature {

    private final SignedJWT signedJWT;
    private final String serialized;
    private final JwsHeaders headers;

    private JsonWebSignature(SignedJWT signedJWT, String serialized) {
        this.signedJWT = signedJWT;
        this.serialized = serialized;
        this.headers = new JwsHeadersImpl(signedJWT.getHeader());
    }

    /**
     * Parse a signed token in its compact serialization form.
     * <p>
     * Only the token format is checked, its signature is not verified.
     *
     * @param token the token in its compact serialization form
     * @return the signed token
     * @throws JwsException if the token is not a well formed signed token
     */
    public static JsonWebSignature parse(String token) throws JwsException {
        try {
            return new JsonWebSignature(SignedJWT.parse(token), token);
        } catch (ParseException ex) {
            throw new JwsException("Invalid JSON Web Signature sequence: " + ex.getMessage(), ex);
        }
    }

    /**
     * The token JOSE headers.
     */
    public JwsHeaders headers() {
        return headers;
    }

    /**
     * The token payload, decoded but not verified.
     */
    public String unverifiedPayload() {
        return signedJWT.getPayload().toString();
    }

    /**
     * The token in its compact serialization form.
     */
    public String serialized() {
        return serialized;
    }

    SignedJWT signedJWT() {
        return signedJWT;
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
        public List<X509Certificate> x509CertificateChain() throws ParseException {
            List<Base64> chain = header.getX509CertChain();
            // the certificates are parsed on demand, the failure message names the invalid certificate
            return chain == null ? null : X509CertChainUtils.parse(chain);
        }

        @Override
        public Object header(String name) {
            return header.toJSONObject().get(name);
        }
    }
}
