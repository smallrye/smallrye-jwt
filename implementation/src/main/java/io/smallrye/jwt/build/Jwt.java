package io.smallrye.jwt.build;

import java.util.Collection;
import java.util.Map;

import javax.json.JsonArray;
import javax.json.JsonObject;

import org.eclipse.microprofile.jwt.JsonWebToken;

import io.smallrye.jwt.build.spi.JwtProvider;

/**
 * Factory class for creating {@link JwtClaimsBuilder} which produces
 * signed, encrypted or signed first and then encrypted JWT tokens.
 *
 * <p>
 * The following example shows how to initialize a {@link JwtClaimsBuilder} from an existing resource
 * containing the claims in a JSON format and produce a signed JWT token with a configured signing key:
 * 
 * <pre>
 * <code>
 * String = Jwt.claims("/tokenClaims.json").sign();
 * </code>
 * </pre>
 * <p>
 * The next example shows how to use {@link JwtClaimsBuilder} to add the claims and encrypt a JSON
 * representation of these claims with a configured encrypting key:
 * 
 * <pre>
 * <code>
 * String = Jwt.claims().issuer("https://issuer.org").claim("custom-claim", "custom-value").encrypt();
 * </code>
 * </pre>
 * <p>
 * The final example shows how to initialize a {@link JwtClaimsBuilder} from an existing resource
 * containing the claims in a JSON format, produce an inner signed JWT token with a configured signing key
 * and encrypt it with a configured encrypting key.
 * 
 * <pre>
 * <code>
 * String = Jwt.claims("/tokenClaims.json").innerSign().encrypt();
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
     * Creates a new instance of {@link JwtClaimsBuilder} from a map of claims.
     *
     * @param claims the map with the claim name and value pairs. Claim value is converted to String unless it is
     *        an instance of {@link Boolean}, {@link Number}, {@link Collection}, {@link Map},
     *        {@link JsonObject} or {@link JsonArray}.
     * @return {@link JwtClaimsBuilder}
     */
    public static JwtClaimsBuilder claims(Map<String, Object> claims) {
        return JwtProvider.provider().claims(claims);
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

    /**
     * Creates a new instance of {@link JwtClaimsBuilder} from {@link JsonWebToken}.
     *
     * @param jwt JsonWebToken token.
     * @return {@link JwtClaimsBuilder}
     */
    public static JwtClaimsBuilder claims(JsonWebToken jwt) {
        return JwtProvider.provider().claims(jwt);
    }
}
