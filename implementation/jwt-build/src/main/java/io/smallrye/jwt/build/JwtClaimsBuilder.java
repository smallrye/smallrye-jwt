package io.smallrye.jwt.build;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Map;
import java.util.Set;

import jakarta.json.JsonArray;
import jakarta.json.JsonObject;

import org.eclipse.microprofile.jwt.Claims;

/**
 * JWT Claims Builder.
 *
 * <p>
 * JwtClaimsBuilder implementations must set the 'iat' (issued at time), 'exp' (expiration time)
 * and 'jti' (unique token identifier) claims unless they have already been set.
 * JwtClaimsBuilder must ensure a 'jti' claim value is unique when the same builder is used for building more than one token.
 * <p>
 * By default the 'iat' claim is set to the current time in seconds and the 'exp' claim is set by adding a default token
 * lifespan value of 5 minutes to the 'iat' claim value. The 'smallrye.jwt.new-token.lifespan' property can be used to
 * customize a new token lifespan and its 'exp' claim values.
 * <p>
 * The 'iss' (issuer) claim must be set if it has not already been set and the 'smallrye.jwt.new-token.issuer' property is set.
 * The 'aud' (audience) claim must be set if it has not already been set and the 'smallrye.jwt.new-token.audience' property is
 * set.
 * <p>
 * Note that 'smallrye.jwt.new-token.issuer' and 'smallrye.jwt.new-token.audience' property values, if set, will override
 * the existing `iss` and `aud` claim values if the 'smallrye.jwt.new-token.override-matching-claims' is set to 'true'.
 * For example, it can be useful when propagating a JWT token whose 'issuer' and/or `audience` properties have to be updated
 * without using this interface.
 * <p>
 * Note that JwtClaimsBuilder implementations are not expected to be thread-safe.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7519">RFC7515</a>
 */
public interface JwtClaimsBuilder extends JwtSignature {

    /**
     * Set an issuer 'iss' claim
     *
     * @param issuer the issuer
     * @return JwtClaimsBuilder
     */
    JwtClaimsBuilder issuer(String issuer);

    /**
     * Set a subject 'sub' claim
     *
     * @param subject the subject
     * @return JwtClaimsBuilder
     */
    JwtClaimsBuilder subject(String subject);

    /**
     * Set a 'upn' claim
     *
     * @param upn the upn
     * @return JwtClaimsBuilder
     */
    JwtClaimsBuilder upn(String upn);

    /**
     * Set a preferred user name 'preferred_username' claim
     *
     * @param preferredUserName the preferred user name
     * @return JwtClaimsBuilder
     */
    JwtClaimsBuilder preferredUserName(String preferredUserName);

    /**
     * Set an issuedAt 'iat' claim
     *
     * @param issuedAt the issuedAt time in seconds
     * @return JwtClaimsBuilder
     */
    JwtClaimsBuilder issuedAt(long issuedAt);

    /**
     * Set an issuedAt 'iat' claim
     *
     * @param issuedAt the issuedAt time in seconds
     * @return JwtClaimsBuilder
     */
    default JwtClaimsBuilder issuedAt(Instant issuedAt) {
        return issuedAt(issuedAt.getEpochSecond());
    }

    /**
     * Set an expiry 'exp' claim
     *
     * @param expiresAt the absolute expiry time in seconds
     * @return JwtClaimsBuilder
     */
    JwtClaimsBuilder expiresAt(long expiresAt);

    /**
     * Set an expiry 'exp' claim
     *
     * @param expiresAt the absolute expiry time in seconds
     * @return JwtClaimsBuilder
     */
    default JwtClaimsBuilder expiresAt(Instant expiresAt) {
        return expiresAt(expiresAt.getEpochSecond());
    }

    /**
     * Set a relative expiry time.
     *
     * @param expiresIn the relative expiry time in seconds which will be added to the 'iat' (issued at) claim value
     *        to calculate the value of the 'exp' (expires at) claim.
     * @return JwtClaimsBuilder
     */
    JwtClaimsBuilder expiresIn(long expiresIn);

    /**
     * Set a relative expiry time.
     *
     * @param expiresIn the relative expiry time in seconds which will be added to the 'iat' (issued at) claim value
     *        to calculate the value of the 'exp' (expires at) claim.
     * @return JwtClaimsBuilder
     */
    default JwtClaimsBuilder expiresIn(Duration expiresIn) {
        return expiresIn(expiresIn.getSeconds());
    }

    /**
     * Set a single value 'groups' claim
     *
     * @param group the groups
     * @return JwtClaimsBuilder
     */
    JwtClaimsBuilder groups(String group);

    /**
     * Set a multiple value 'groups' claim
     *
     * @param groups the groups
     * @return JwtClaimsBuilder
     */
    JwtClaimsBuilder groups(Set<String> groups);

    /**
     * Set a single value audience 'aud' claim
     *
     * @param audience the audience
     * @return JwtClaimsBuilder
     */
    JwtClaimsBuilder audience(String audience);

    /**
     * Set a multiple value audience 'aud' claim
     *
     * @param audiences the audiences
     * @return JwtClaimsBuilder
     */
    JwtClaimsBuilder audience(Set<String> audiences);

    /**
     * Set a claim.
     *
     * Simple claim value are converted to {@link String} unless it is an instance of {@link Boolean}, {@link Number} or
     * {@link Instant}. {@link Instant} values have their number of seconds from the epoch converted to long.
     *
     * Array claims can be set as {@link Collection} or {@link JsonArray} and complex claims can be set as {@link Map} or
     * {@link JsonObject}. The members of the array claims can be complex claims.
     *
     * Types of claims directly supported by this builder are enforced.
     * The 'iss' (issuer), 'sub' (subject), 'upn', 'preferred_username' and 'jti' (token identifier) claims must be of
     * {@link String} type.
     * The 'aud' (audience) and 'groups' claims must be either of {@link String} or {@link Collection} of {@link String} type.
     * The 'iat' (issued at) and 'exp' (expires at) claims must be either of long or {@link Instant} type.
     *
     * @param name the claim name
     * @param value the claim value
     * @throws IllegalArgumentException - if the type of the claim directly supported by this builder is wrong
     * @return JwtClaimsBuilder
     */
    default JwtClaimsBuilder claim(Claims name, Object value) {
        return claim(name.name(), value);
    }

    /**
     * Set a claim.
     *
     * Simple claim value are converted to {@link String} unless it is an instance of {@link Boolean}, {@link Number} or
     * {@link Instant}. {@link Instant} values have their number of seconds from the epoch converted to long.
     *
     * Array claims can be set as {@link Collection} or {@link JsonArray}, complex claims can be set as {@link Map} or
     * {@link JsonObject}. The members of the array claims can be complex claims.
     *
     * Types of the claims directly supported by this builder are enforced.
     * The 'iss' (issuer), 'sub' (subject), 'upn', 'preferred_username' and 'jti' (token identifier) claims must be of
     * {@link String} type.
     * The 'aud' (audience) and 'groups' claims must be either of {@link String} or {@link Collection} of {@link String} type.
     * The 'iat' (issued at) and 'exp' (expires at) claims must be either of long or {@link Instant} type.
     *
     * @param name the claim name
     * @param value the claim value
     * @throws IllegalArgumentException - if the type of the claim directly supported by this builder is wrong
     * @return JwtClaimsBuilder
     */
    JwtClaimsBuilder claim(String name, Object value);

    /**
     * Remove a claim.
     *
     * @param name the claim name
     * @return JwtClaimsBuilder
     */
    JwtClaimsBuilder remove(String name);

    /**
     * Set JsonWebSignature headers and sign the claims by moving to {@link JwtSignatureBuilder}
     *
     * @return JwtSignatureBuilder
     */
    JwtSignatureBuilder jws();

    /**
     * Set JsonWebEncryption headers and encrypt the claims by moving to {@link JwtEncryptionBuilder}
     *
     * @return JwtSignatureBuilder
     */
    JwtEncryptionBuilder jwe();
}
