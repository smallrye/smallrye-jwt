package io.smallrye.jwt.auth;

import java.security.Key;
import java.util.HashSet;
import java.util.Set;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.SignedJWT;

import io.smallrye.jwt.auth.principal.JsonWebSignatureImpl;
import io.smallrye.jwt.auth.principal.SingleKeyVerificationKeyResolver;

/**
 * A builder-style JWS verifier that encapsulates parsing, the allowed-algorithm check,
 * key resolution and signature verification.
 * <p>
 * It deals with the JWS signature layer only: verification fails by throwing, and the token claims are
 * neither returned nor validated. Use {@link JwtVerifier} to verify a token and get its validated claims.
 * A verification key can be supplied directly with {@link Builder#key(Key)} or resolved from the token with
 * {@link Builder#verificationKeyResolver(VerificationKeyResolver)}.
 */
public class JwsVerifier {

    private final VerificationKeyResolver keyResolver;
    private final Set<String> allowedAlgorithms;

    private JwsVerifier(Builder builder) {
        this.keyResolver = builder.keyResolver;
        this.allowedAlgorithms = builder.allowedAlgorithms;
    }

    public void verify(String token) throws InvalidJWTException, UnresolvableKeyException {
        final SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(token);
        } catch (java.text.ParseException e) {
            // Nimbus throws java.text.ParseException when parsing a malformed token.
            throw new InvalidJWTException("Invalid JWT token format", e);
        }

        JWSHeader header = signedJWT.getHeader();
        String alg = header.getAlgorithm().getName();

        if (!allowedAlgorithms.contains(alg)) {
            throw new InvalidJWTException("Algorithm " + alg + " is not allowed");
        }

        Key key = keyResolver.resolveKey(new JsonWebSignatureImpl(signedJWT, token));

        boolean signatureValid;
        try {
            JWSVerifier verifier = JwtVerifier.createVerifier(key, header.getAlgorithm());
            signatureValid = signedJWT.verify(verifier);
        } catch (JOSEException e) {
            // Nimbus reports a cryptographic failure via JOSEException; keep it as the cause for debugging.
            throw new InvalidJWTException("Token signature verification failed", e);
        }
        if (!signatureValid) {
            // Nimbus signals a failed signature by returning false rather than throwing.
            throw new InvalidJWTException("Token signature verification failed");
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private VerificationKeyResolver keyResolver;
        private Set<String> allowedAlgorithms;

        /**
         * Verify the signature with a pre-configured key. The key is wrapped in a
         * {@link SingleKeyVerificationKeyResolver}.
         */
        public Builder key(Key key) {
            this.keyResolver = new SingleKeyVerificationKeyResolver(key);
            return this;
        }

        public Builder verificationKeyResolver(VerificationKeyResolver resolver) {
            this.keyResolver = resolver;
            return this;
        }

        public Builder allowedAlgorithms(Set<String> algorithms) {
            this.allowedAlgorithms = algorithms != null ? new HashSet<>(algorithms) : null;
            return this;
        }

        public JwsVerifier build() {
            if (keyResolver == null) {
                throw new IllegalStateException("A verification key or a VerificationKeyResolver is required");
            }
            if (allowedAlgorithms == null || allowedAlgorithms.isEmpty()) {
                throw new IllegalStateException("At least one allowed algorithm is required");
            }
            return new JwsVerifier(this);
        }
    }
}
