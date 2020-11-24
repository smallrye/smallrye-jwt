package io.smallrye.jwt.algorithm;

/**
 * * JWT JSON Web Content Encryption Algorithms.
 * 
 * @see <a href="https://tools.ietf.org/html/rfc7518#section-5">https://tools.ietf.org/html/rfc7518#section-5</a>
 */
public enum ContentEncryptionAlgorithm {
    A128GCM("A128GCM"),
    A192GCM("A192GCM"),
    A256GCM("A256GCM"),
    A128CBC_HS256("A128CBC-HS256"),
    A192CBC_HS384("A192CBC-HS384"),
    A256CBC_HS512("A256CBC-HS512");

    private String algorithmName;

    private ContentEncryptionAlgorithm(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    public String getAlgorithm() {
        return algorithmName;
    }

    public static ContentEncryptionAlgorithm fromAlgorithm(String algorithmName) {
        return ContentEncryptionAlgorithm.valueOf(algorithmName.replaceAll("-", "_").replaceAll("\\+", "_"));
    }
}
