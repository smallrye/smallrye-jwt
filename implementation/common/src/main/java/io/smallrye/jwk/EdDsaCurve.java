package io.smallrye.jwk;

/**
 * The curves which can be used with the EdDSA JSON Web Keys.
 */
public enum EdDsaCurve {

    ED25519("Ed25519"),
    ED448("Ed448");

    private final String name;

    EdDsaCurve(String name) {
        this.name = name;
    }

    /**
     * The `crv` curve name, for example, `Ed25519`.
     *
     * @return the curve name
     */
    public String getName() {
        return name;
    }
}
