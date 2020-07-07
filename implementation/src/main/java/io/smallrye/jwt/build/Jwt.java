package io.smallrye.jwt.build;

import java.util.Collection;
import java.util.Map;
import java.util.Set;

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
     * Creates a new instance of {@link JwtClaimsBuilder} from {@link JsonObject}
     *
     * @param jsonObject {@link JsonObject} containing the claims.
     * @return {@link JwtClaimsBuilder}
     */
    public static JwtClaimsBuilder claims(JsonObject jsonObject) {
        return JwtProvider.provider().claims(jsonObject);
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

    /**
     * Creates a new instance of {@link JwtClaimsBuilder} with a specified claim.
     *
     * @param name the claim name
     * @param value the claim value
     * @return {@link JwtClaimsBuilder}
     */
    public static JwtClaimsBuilder claim(String name, Object value) {
        return claims().claim(name, value);
    }

    /**
     * Creates a new instance of {@link JwtClaimsBuilder} with a specified issuer.
     *
     * @param issuer the issuer
     * @return {@link JwtClaimsBuilder}
     */
    public static JwtClaimsBuilder issuer(String issuer) {
        return claims().issuer(issuer);
    }

    /**
     * Creates a new instance of {@link JwtClaimsBuilder} with a specified subject.
     *
     * @param subject the subject
     * @return {@link JwtClaimsBuilder}
     */
    public static JwtClaimsBuilder subject(String subject) {
        return claims().subject(subject);
    }

    /**
     * Creates a new instance of {@link JwtClaimsBuilder} with a specified 'groups' claim.
     *
     * @param groups the groups
     * @return {@link JwtClaimsBuilder}
     */
    public static JwtClaimsBuilder groups(String groups) {
        return claims().groups(groups);
    }

    /**
     * Creates a new instance of {@link JwtClaimsBuilder} with a specified 'groups' claim.
     *
     * @param groups the groups
     * @return {@link JwtClaimsBuilder}
     */
    public static JwtClaimsBuilder groups(Set<String> groups) {
        return claims().groups(groups);
    }

    /**
     * Creates a new instance of {@link JwtClaimsBuilder} with a specified 'audience' claim.
     *
     * @param audience the audience
     * @return {@link JwtClaimsBuilder}
     */
    public static JwtClaimsBuilder audience(String audience) {
        return claims().audience(audience);
    }

    /**
     * Creates a new instance of {@link JwtClaimsBuilder} with a specified 'audience' claim.
     *
     * @param audiences the audience
     * @return {@link JwtClaimsBuilder}
     */
    public static JwtClaimsBuilder audience(Set<String> audiences) {
        return claims().audience(audiences);
    }

    /**
     * Creates a new instance of {@link JwtClaimsBuilder} with a specified 'upn' claim.
     *
     * @param upn the upn
     * @return {@link JwtClaimsBuilder}
     */
    public static JwtClaimsBuilder upn(String upn) {
        return claims().upn(upn);
    }

    /**
     * Creates a new instance of {@link JwtClaimsBuilder} with a specified 'preferred_username' claim.
     *
     * @param preferredUserName the preferred user name
     * @return {@link JwtClaimsBuilder}
     */
    public static JwtClaimsBuilder preferredUserName(String preferredUserName) {
        return claims().preferredUserName(preferredUserName);
    }

    /**
     * Sign the claims loaded from a JSON resource using 'RS256' algorithm with a private RSA key
     * loaded from the location set with the "smallrye.jwt.sign.key-location".
     * Private RSA key of size 2048 bits or larger MUST be used.
     *
     * The 'iat' (issued at time), 'exp' (expiration time) and 'jit' (unique token identifier) claims
     * will be and the `iss` issuer claim may be set by the implementation unless they have already been set.
     * See {@link JwtClaimsBuilder} description for more information.
     *
     * @param jsonLocation JSON resource location
     * @return signed JWT token
     * @throws JwtSignatureException the exception if the signing operation has failed
     */
    public static String sign(String jsonLocation) {
        return claims(jsonLocation).sign();
    }

    /**
     * Sign the claims using 'RS256' algorithm with a private RSA key
     * loaded from the location set with the "smallrye.jwt.sign.key-location".
     * Private RSA key of size 2048 bits or larger MUST be used.
     *
     * The 'iat' (issued at time), 'exp' (expiration time) and 'jit' (unique token identifier) claims
     * will be and the `iss` issuer claim may be set by the implementation unless they have already been set.
     * See {@link JwtClaimsBuilder} description for more information.
     *
     * @param claims the map with the claim name and value pairs. Claim value is converted to String unless it is
     *        an instance of {@link Boolean}, {@link Number}, {@link Collection}, {@link Map},
     *        {@link JsonObject} or {@link JsonArray}
     * @return signed JWT token
     * @throws JwtSignatureException the exception if the signing operation has failed
     */
    public static String sign(Map<String, Object> claims) {
        return claims(claims).sign();
    }

    /**
     * Sign the claims loaded from {@link JsonObject} using 'RS256' algorithm with a private RSA key
     * loaded from the location set with the "smallrye.jwt.sign.key-location".
     * Private RSA key of size 2048 bits or larger MUST be used.
     *
     * The 'iat' (issued at time), 'exp' (expiration time) and 'jit' (unique token identifier) claims
     * will be and the `iss` issuer claim may be set by the implementation unless they have already been set.
     * See {@link JwtClaimsBuilder} description for more information.
     *
     * @param jsonObject {@link JsonObject} containing the claims.
     * @return signed JWT token
     * @throws JwtSignatureException the exception if the signing operation has failed
     */
    public static String sign(JsonObject jsonObject) {
        return claims(jsonObject).sign();
    }

    /**
     * Encrypt the claims loaded from a JSON resource using 'RSA-OAEP-256' algorithm with a public RSA key
     * loaded from the location set with the "smallrye.jwt.encrypt.key-location".
     * Public RSA key of size 2048 bits or larger MUST be used.
     *
     * The 'iat' (issued at time), 'exp' (expiration time) and 'jit' (unique token identifier) claims
     * will be and the `iss` issuer claim may be set by the implementation unless they have already been set.
     * See {@link JwtClaimsBuilder} description for more information.
     *
     * @param jsonLocation JSON resource location
     * @return encrypted JWT token
     * @throws JwtEncryptionException the exception if the encryption operation has failed
     */
    public static String encrypt(String jsonLocation) {
        return claims(jsonLocation).jwe().encrypt();
    }

    /**
     * Encrypt the claims using 'RSA-OAEP-256' algorithm with a public RSA key
     * loaded from the location set with the "smallrye.jwt.encrypt.key-location".
     * Public RSA key of size 2048 bits or larger MUST be used.
     *
     * The 'iat' (issued at time), 'exp' (expiration time) and 'jit' (unique token identifier) claims
     * will be and the `iss` issuer claim may be set by the implementation unless they have already been set.
     * See {@link JwtClaimsBuilder} description for more information.
     *
     * @param claims the map with the claim name and value pairs. Claim value is converted to String unless it is
     *        an instance of {@link Boolean}, {@link Number}, {@link Collection}, {@link Map},
     *        {@link JsonObject} or {@link JsonArray}
     * @return encrypted JWT token
     * @throws JwtEncryptionException the exception if the encryption operation has failed
     */
    public static String encrypt(Map<String, Object> claims) {
        return claims(claims).jwe().encrypt();
    }

    /**
     * Encrypt the claims loaded from {@link JsonObject} using 'RSA-OAEP-256' algorithm with a public RSA key
     * loaded from the location set with the "smallrye.jwt.encrypt.key-location".
     * Public RSA key of size 2048 bits or larger MUST be used.
     *
     * The 'iat' (issued at time), 'exp' (expiration time) and 'jit' (unique token identifier) claims
     * will be and the `iss` issuer claim may be set by the implementation unless they have already been set.
     * See {@link JwtClaimsBuilder} description for more information.
     *
     * @param jsonObject {@link JsonObject} containing the claims.
     * @return encrypted JWT token
     * @throws JwtEncryptionException the exception if the encryption operation has failed
     */
    public static String encrypt(JsonObject jsonObject) {
        return claims(jsonObject).jwe().encrypt();
    }

    /**
     * Sign the claims loaded from a JSON resource using 'RS256' algorithm with a private RSA key
     * loaded from the location set with the "smallrye.jwt.sign.key-location" and encrypt the inner JWT using
     * 'RSA-OAEP-256' algorithm with a public RSA key loaded from the location set with the "smallrye.jwt.encrypt.key-location".
     * Public RSA key of size 2048 bits or larger MUST be used.
     *
     * The 'iat' (issued at time), 'exp' (expiration time) and 'jit' (unique token identifier) claims
     * will be and the `iss` issuer claim may be set by the implementation unless they have already been set.
     * See {@link JwtClaimsBuilder} description for more information.
     *
     * @param jsonLocation JSON resource location
     * @return encrypted JWT token
     * @throws JwtEncryptionException the exception if the encryption operation has failed
     */
    public static String innerSignAndEncrypt(String jsonLocation) {
        return claims(jsonLocation).innerSign().encrypt();
    }

    /**
     * Sign the claims using 'RS256' algorithm with a private RSA key
     * loaded from the location set with the "smallrye.jwt.sign.key-location" and encrypt the inner JWT using
     * 'RSA-OAEP-256' algorithm with a public RSA key loaded from the location set with the "smallrye.jwt.encrypt.key-location".
     * Public RSA key of size 2048 bits or larger MUST be used.
     *
     * The 'iat' (issued at time), 'exp' (expiration time) and 'jit' (unique token identifier) claims
     * will be and the `iss` issuer claim may be set by the implementation unless they have already been set.
     * See {@link JwtClaimsBuilder} description for more information.
     *
     * @param claims the map with the claim name and value pairs. Claim value is converted to String unless it is
     *        an instance of {@link Boolean}, {@link Number}, {@link Collection}, {@link Map},
     *        {@link JsonObject} or {@link JsonArray}
     * @return encrypted JWT token
     * @throws JwtEncryptionException the exception if the encryption operation has failed
     */
    public static String innerSignAndEncrypt(Map<String, Object> claims) {
        return claims(claims).innerSign().encrypt();
    }

    /**
     * Sign the claims loaded from {@link JsonObject} using 'RS256' algorithm with a private RSA key
     * loaded from the location set with the "smallrye.jwt.sign.key-location" and encrypt the inner JWT using
     * 'RSA-OAEP-256' algorithm with a public RSA key loaded from the location set with the "smallrye.jwt.encrypt.key-location".
     * Public RSA key of size 2048 bits or larger MUST be used.
     *
     * The 'iat' (issued at time), 'exp' (expiration time) and 'jit' (unique token identifier) claims
     * will be and the `iss` issuer claim may be set by the implementation unless they have already been set.
     * See {@link JwtClaimsBuilder} description for more information.
     *
     * @param jsonObject {@link JsonObject} containing the claims.
     * @return encrypted JWT token
     * @throws JwtEncryptionException the exception if the encryption operation has failed
     */
    public static String innerSignAndEncrypt(JsonObject jsonObject) {
        return claims(jsonObject).innerSign().encrypt();
    }
}
