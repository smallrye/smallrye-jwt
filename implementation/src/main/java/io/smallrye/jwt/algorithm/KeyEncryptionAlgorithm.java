package io.smallrye.jwt.algorithm;

/**
 * JWT JSON Web Key Encryption (Management) Algorithms.
 * 
 * @see <a href="https://tools.ietf.org/html/rfc7518#section-4">https://tools.ietf.org/html/rfc7518#section-4</a>
 */
public enum KeyEncryptionAlgorithm {
    RSA_OAEP_256("RSA-OAEP-256"),
    ECDH_ES_A256KW("ECDH-ES+A256KW"),
    A256KW("A256KW");

    private String algorithmName;

    private KeyEncryptionAlgorithm(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    public String getAlgorithm() {
        return algorithmName;
    }

    public static KeyEncryptionAlgorithm fromAlgorithm(String algorithmName) {
        return KeyEncryptionAlgorithm.valueOf(algorithmName.replaceAll("-", "_").replaceAll("\\+", "_"));
    }
}
