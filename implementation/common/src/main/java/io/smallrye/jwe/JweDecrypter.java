package io.smallrye.jwe;

import java.security.Key;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.XECPrivateKey;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.AESDecrypter;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.PasswordBasedDecrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;

import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.jwt.algorithm.XDHDecrypter;

/**
 * Decrypts a JSON Web Encryption compact sequence to a string.
 * <p>
 * The decrypted content is an arbitrary string such as a signed JWT token or any other text.
 */
public class JweDecrypter {

    private final Key key;
    private final Set<String> keyAlgorithms;

    private JweDecrypter(Key key, Set<KeyEncryptionAlgorithm> keyAlgorithms) {
        this.key = key;
        this.keyAlgorithms = keyAlgorithms.stream().map(KeyEncryptionAlgorithm::getAlgorithm).collect(Collectors.toSet());
    }

    /**
     * Create a builder of a decrypter which will use the given key decryption key.
     *
     * @param key the RSA or EC private key or the secret key
     * @return the builder
     */
    public static Builder builder(Key key) {
        return new Builder(key);
    }

    /**
     * Decrypt the JSON Web Encryption sequence.
     *
     * @param jwe the JSON Web Encryption compact sequence
     * @return the decrypted content
     * @throws JweException if the sequence is invalid or can not be decrypted
     */
    public String decrypt(String jwe) throws JweException {
        return decrypt(JsonWebEncryption.parse(jwe));
    }

    /**
     * Decrypt the already parsed JSON Web Encryption sequence.
     *
     * @param jwe the parsed JSON Web Encryption sequence
     * @return the decrypted content
     * @throws JweException if the sequence can not be decrypted
     */
    public String decrypt(JsonWebEncryption jwe) throws JweException {
        String algorithm = jwe.headers().algorithm();
        if (!keyAlgorithms.contains(algorithm)) {
            throw new JweException("Key encryption algorithm " + algorithm + " is not allowed");
        }

        JWEObject jweObject = jwe.jweObject();
        if (jweObject.getState() != JWEObject.State.ENCRYPTED) {
            throw new JweException("The JSON Web Encryption sequence has already been decrypted");
        }

        try {
            jweObject.decrypt(createDecrypter(key, algorithm, jweObject.getHeader()));
        } catch (JOSEException | IllegalArgumentException ex) {
            // Nimbus throws IllegalArgumentException for the invalid keys, for example, RSA keys shorter than 2048 bits
            throw new JweException("Failed to decrypt the JSON Web Encryption sequence: " + ex.getMessage(), ex);
        }
        return jweObject.getPayload().toString();
    }

    private static JWEDecrypter createDecrypter(Key key, String algorithm, JWEHeader header) throws JOSEException {
        // Opaque RSA and EC private keys, for example, PKCS#11 keys, do not implement RSAPrivateKey or ECPrivateKey
        if (key instanceof RSAPrivateKey || (key instanceof PrivateKey && "RSA".equalsIgnoreCase(key.getAlgorithm()))) {
            return new RSADecrypter((PrivateKey) key);
        } else if (key instanceof ECPrivateKey) {
            return new ECDHDecrypter((ECPrivateKey) key);
        } else if (key instanceof PrivateKey && "EC".equalsIgnoreCase(key.getAlgorithm())) {
            // The curve of an opaque EC private key is not available, it must match the ephemeral public key curve
            JWK epk = header.getEphemeralPublicKey();
            if (!(epk instanceof ECKey)) {
                throw new JOSEException("Missing or invalid ephemeral public key in the JWE header");
            }
            return new ECDHDecrypter((PrivateKey) key, null, ((ECKey) epk).getCurve());
        } else if (key instanceof SecretKey) {
            SecretKey secretKey = (SecretKey) key;
            if (KeyEncryptionAlgorithm.DIR.getAlgorithm().equals(algorithm)) {
                return new DirectDecrypter(secretKey);
            }
            if (algorithm != null && algorithm.startsWith("PBES2")) {
                // raw key bytes, as jose4j did, decoding them as UTF-8 text can corrupt them
                return new PasswordBasedDecrypter(secretKey.getEncoded());
            }
            return new AESDecrypter(secretKey);
        } else if (key instanceof XECPrivateKey) {
            return XDHDecrypter.fromXECPrivateKey((XECPrivateKey) key);
        }
        throw new JOSEException("Unsupported key type for decryption: " + key.getClass().getName());
    }

    /**
     * A builder of a {@link JweDecrypter}.
     */
    public static class Builder {

        private final Key key;
        private Set<KeyEncryptionAlgorithm> keyAlgorithms;

        private Builder(Key key) {
            this.key = key;
        }

        /**
         * Set the only `alg` key encryption algorithm which is accepted during the decryption.
         *
         * @param keyAlgorithm the key encryption algorithm
         * @return this builder
         */
        public Builder keyAlgorithm(KeyEncryptionAlgorithm keyAlgorithm) {
            return keyAlgorithms(keyAlgorithm != null ? Set.of(keyAlgorithm) : null);
        }

        /**
         * Set the `alg` key encryption algorithms which are accepted during the decryption.
         *
         * @param keyAlgorithms the key encryption algorithms
         * @return this builder
         */
        public Builder keyAlgorithms(Set<KeyEncryptionAlgorithm> keyAlgorithms) {
            this.keyAlgorithms = keyAlgorithms != null && !keyAlgorithms.isEmpty() ? new HashSet<>(keyAlgorithms) : null;
            return this;
        }

        /**
         * Build the decrypter.
         *
         * @return the decrypter
         * @throws JweException if the key or the accepted key encryption algorithms are not set
         */
        public JweDecrypter build() throws JweException {
            if (key == null) {
                throw new JweException("Key decryption key is not set");
            }
            if (keyAlgorithms == null || keyAlgorithms.isEmpty()) {
                throw new JweException("At least one accepted key encryption algorithm is required");
            }
            return new JweDecrypter(key, keyAlgorithms);
        }
    }
}
