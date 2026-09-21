package io.smallrye.jws;

import java.security.Key;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.SecretKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;

import io.smallrye.jwt.algorithm.EdDSAVerifier;

/**
 * Verifies the signature of a JSON Web Signature compact sequence with a given key.
 * <p>
 * The verified content is an arbitrary string, which can be a JSON document, a set of JSON Web Token
 * claims or any other text. Only the signature is verified, the content itself is neither interpreted
 * nor validated.
 */
public class JwsVerifier {

    private final Key key;
    private final Set<String> algorithms;

    private JwsVerifier(Key key, Set<String> algorithms) {
        this.key = key;
        this.algorithms = algorithms;
    }

    /**
     * Create a builder of a verifier which will use the given verification key.
     *
     * @param key the RSA, EC or EdDSA public key or the secret key
     * @return the builder
     */
    public static Builder builder(Key key) {
        return new Builder(key);
    }

    /**
     * Verify the JSON Web Signature sequence.
     *
     * @param jws the JSON Web Signature compact sequence
     * @return the verified content
     * @throws JwsException if the sequence is invalid or its signature can not be verified
     */
    public String verify(String jws) throws JwsException {
        return verify(JsonWebSignature.parse(jws));
    }

    /**
     * Verify the already parsed JSON Web Signature sequence.
     *
     * @param jws the parsed JSON Web Signature sequence
     * @return the verified content
     * @throws JwsException if the signature can not be verified
     */
    public String verify(JsonWebSignature jws) throws JwsException {
        String algorithm = jws.headers().algorithm();
        if (!algorithms.contains(algorithm)) {
            throw new JwsException("Signature algorithm " + algorithm + " is not allowed");
        }

        SignedJWT signedJWT = jws.signedJWT();

        boolean verified;
        try {
            verified = signedJWT.verify(createVerifier(key, signedJWT.getHeader().getAlgorithm()));
        } catch (JOSEException ex) {
            throw new JwsException("Failed to verify the JSON Web Signature sequence: " + ex.getMessage(), ex);
        }
        if (!verified) {
            // Nimbus signals a failed signature by returning false rather than throwing.
            throw new JwsException("The JSON Web Signature sequence signature is invalid");
        }
        return signedJWT.getPayload().toString();
    }

    private static JWSVerifier createVerifier(Key key, JWSAlgorithm algorithm) throws JOSEException {
        if (key instanceof RSAPublicKey) {
            return new RSASSAVerifier((RSAPublicKey) key);
        } else if (key instanceof ECPublicKey) {
            return new ECDSAVerifier((ECPublicKey) key);
        } else if (key instanceof SecretKey) {
            return new MACVerifier((SecretKey) key);
        } else if (key instanceof EdECPublicKey) {
            return new EdDSAVerifier((PublicKey) key);
        }
        throw new JOSEException("Unsupported key type for verification: " + key.getClass().getName());
    }

    /**
     * A builder of a {@link JwsVerifier}.
     */
    public static class Builder {

        private final Key key;
        private Set<String> algorithms;

        private Builder(Key key) {
            this.key = key;
        }

        /**
         * Set the only `alg` signature algorithm which is accepted during the verification.
         *
         * @param algorithm the signature algorithm
         * @return this builder
         */
        public Builder algorithm(String algorithm) {
            return algorithms(algorithm != null ? Set.of(algorithm) : null);
        }

        /**
         * Set the `alg` signature algorithms which are accepted during the verification.
         *
         * @param algorithms the signature algorithms
         * @return this builder
         */
        public Builder algorithms(Set<String> algorithms) {
            this.algorithms = algorithms != null ? new HashSet<>(algorithms) : null;
            return this;
        }

        /**
         * Build the verifier.
         *
         * @return the verifier
         * @throws JwsException if the key or the accepted algorithms are not set
         */
        public JwsVerifier build() throws JwsException {
            if (key == null) {
                throw new JwsException("Verification key is not set");
            }
            if (algorithms == null || algorithms.isEmpty()) {
                throw new JwsException("At least one accepted signature algorithm is required");
            }
            return new JwsVerifier(key, algorithms);
        }
    }
}
