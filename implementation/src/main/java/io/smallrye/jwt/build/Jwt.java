package io.smallrye.jwt.build;

import io.smallrye.jwt.build.spi.JwtProvider;

/**
 * Factory class for creating {@link JwtClaimsBuilder} objects.
 *
 * <p>
 * The following example shows how to create a {@link JwtClaimsBuilder} to start creating a signed JWT token:
 * 
 * <pre>
 * <code>
 * JwtClaimsBuilder claims = Jwt.claims();
 * </code>
 * </pre>
 */
public final class Jwt {

    /**
     * Creates a new instance of {@link JwtClaimsBuilder}
     *
     * @return {@link JwtClaimsBuilder}
     */
    public static JwtClaimsBuilder claims() {
        return JwtProvider.provider().claims();
    }

    /**
     * Creates a new instance of {@link JwtClaimsBuilder} from a JSON resource.
     * 
     * @param jsonLocation JSON resource location
     * @return {@link JwtClaimsBuilder}
     */
    public static JwtClaimsBuilder claims(String jsonLocation) {
        return JwtProvider.provider().claims(jsonLocation);
    }
}
