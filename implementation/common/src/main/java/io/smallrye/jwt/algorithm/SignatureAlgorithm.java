package io.smallrye.jwt.algorithm;

/**
 * JWT JSON Web Signature Algorithms.
 * 
 * @see <a href="https://tools.ietf.org/html/rfc7518#section-3">https://tools.ietf.org/html/rfc7518#section-3</a>
 */
public enum SignatureAlgorithm {
    RS256("RS256"),
    RS384("RS384"),
    RS512("RS512"),
    ES256("ES256"),
    ES384("ES384"),
    ES512("ES512"),
    EDDSA("EdDSA"),
    HS256("HS256"),
    HS384("HS384"),
    HS512("HS512"),
    PS256("PS256"),
    PS384("PS384"),
    PS512("PS512");

    private String algorithmName;

    private SignatureAlgorithm(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    public String getAlgorithm() {
        return algorithmName;
    }

    public static SignatureAlgorithm fromAlgorithm(String algorithmName) {
        return SignatureAlgorithm.valueOf(algorithmName);
    }
}
