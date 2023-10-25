package io.smallrye.jwt.algorithm;

/**
 * JWT JSON Web Key Encryption (Management) Algorithms.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7518#section-4">https://tools.ietf.org/html/rfc7518#section-4</a>
 */
public enum KeyEncryptionAlgorithm {
    RSA_OAEP("RSA-OAEP"),
    RSA_OAEP_256("RSA-OAEP-256"),
    ECDH_ES("ECDH-ES"),
    ECDH_ES_A128KW("ECDH-ES+A128KW"),
    ECDH_ES_A192KW("ECDH-ES+A192KW"),
    ECDH_ES_A256KW("ECDH-ES+A256KW"),
    A128KW("A128KW"),
    A192KW("A192KW"),
    A256KW("A256KW"),
    A128GCMKW("A128GCMKW"),
    A192GCMKW("A192GCMKW"),
    A256GCMKW("A256GCMKW"),
    PBES2_HS256_A128KW("PBES2-HS256+A128KW"),
    PBES2_HS384_A192KW("PBES2-HS384+A192KW"),
    PBES2_HS512_A256KW("PBES2-HS512+A256KW"),
    DIR("dir");

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
