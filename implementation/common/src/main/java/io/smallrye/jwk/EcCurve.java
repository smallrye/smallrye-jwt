package io.smallrye.jwk;

/**
 * The elliptic curves which can be used with the EC JSON Web Keys.
 */
public enum EcCurve {

    P_256("P-256", "secp256r1"),
    P_384("P-384", "secp384r1"),
    P_521("P-521", "secp521r1");

    private final String name;
    private final String parameterSpec;

    EcCurve(String name, String parameterSpec) {
        this.name = name;
        this.parameterSpec = parameterSpec;
    }

    /**
     * The `crv` curve name, for example, `P-256`.
     *
     * @return the curve name
     */
    public String getName() {
        return name;
    }

    /**
     * The standard name of the curve parameters, for example, `secp256r1`.
     *
     * @return the curve parameter specification name
     */
    public String getParameterSpec() {
        return parameterSpec;
    }
}
