package io.smallrye.jwt.algorithm;

/**
 * JWT JSON Web Signature Algorithms.
 * 
 * @see <a href="https://tools.ietf.org/html/rfc7518#section-3">https://tools.ietf.org/html/rfc7518#section-3</a>
 */
public enum SignatureAlgorithm {
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    ES512,
    ES256K,
    HS256,
    HS384,
    HS512,
    PS256,
    PS384,
    PS512;

    public String getAlgorithm() {
        return this.name();
    }

    public static SignatureAlgorithm fromAlgorithm(String algorithmName) {
        return SignatureAlgorithm.valueOf(algorithmName);
    }
}
