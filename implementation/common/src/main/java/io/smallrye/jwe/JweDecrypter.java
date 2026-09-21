package io.smallrye.jwe;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.XECPrivateKey;

import javax.crypto.SecretKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.AESDecrypter;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.PasswordBasedDecrypter;
import com.nimbusds.jose.crypto.RSADecrypter;

import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.jwt.algorithm.XDHDecrypter;

/**
 * Decrypts a JSON Web Encryption compact sequence to a string.
 * <p>
 * The decrypted content is an arbitrary string, which can be a JSON document, an already signed
 * JSON Web Token or any other text.
 */
public class JweDecrypter {

    private final Key key;
    private final KeyEncryptionAlgorithm keyAlgorithm;

    private JweDecrypter(Key key, KeyEncryptionAlgorithm keyAlgorithm) {
        this.key = key;
        this.keyAlgorithm = keyAlgorithm;
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
     * <p>
     * The sequence can be decrypted only once.
     *
     * @param jwe the parsed JSON Web Encryption sequence
     * @return the decrypted content
     * @throws JweException if the sequence has already been decrypted or can not be decrypted
     */
    public String decrypt(JsonWebEncryption jwe) throws JweException {
        String algorithm = jwe.headers().algorithm();
        if (keyAlgorithm != null && !keyAlgorithm.getAlgorithm().equals(algorithm)) {
            throw new JweException("Key encryption algorithm " + algorithm + " is not allowed");
        }

        JWEObject jweObject = jwe.jweObject();
        if (jweObject.getState() != JWEObject.State.ENCRYPTED) {
            throw new JweException("The JSON Web Encryption sequence has already been decrypted");
        }

        try {
            jweObject.decrypt(createDecrypter(key, algorithm));
        } catch (JOSEException ex) {
            throw new JweException("Failed to decrypt the JSON Web Encryption sequence: " + ex.getMessage(), ex);
        }
        return jweObject.getPayload().toString();
    }

    private static JWEDecrypter createDecrypter(Key key, String algorithm) throws JOSEException {
        if (key instanceof RSAPrivateKey) {
            return new RSADecrypter((RSAPrivateKey) key);
        } else if (key instanceof ECPrivateKey) {
            return new ECDHDecrypter((ECPrivateKey) key);
        } else if (key instanceof SecretKey) {
            SecretKey secretKey = (SecretKey) key;
            if (KeyEncryptionAlgorithm.DIR.getAlgorithm().equals(algorithm)) {
                return new DirectDecrypter(secretKey);
            }
            if (algorithm != null && algorithm.startsWith("PBES2")) {
                String password = new String(secretKey.getEncoded(), StandardCharsets.UTF_8);
                return new PasswordBasedDecrypter(password);
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
        private KeyEncryptionAlgorithm keyAlgorithm;

        private Builder(Key key) {
            this.key = key;
        }

        /**
         * Set the only `alg` key encryption algorithm which is accepted during the decryption.
         * <p>
         * If it is not set then the algorithm which the JSON Web Encryption sequence advertises is used.
         *
         * @param keyAlgorithm the key encryption algorithm
         * @return this builder
         */
        public Builder keyAlgorithm(KeyEncryptionAlgorithm keyAlgorithm) {
            this.keyAlgorithm = keyAlgorithm;
            return this;
        }

        /**
         * Build the decrypter.
         *
         * @return the decrypter
         * @throws JweException if the key is not set
         */
        public JweDecrypter build() throws JweException {
            if (key == null) {
                throw new JweException("Key decryption key is not set");
            }
            return new JweDecrypter(key, keyAlgorithm);
        }
    }
}
