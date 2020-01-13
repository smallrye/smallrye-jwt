package io.smallrye.jwt.build;

import java.util.Collection;
import java.util.Map;
import java.util.Set;

import javax.json.JsonArray;
import javax.json.JsonObject;

/**
 * JWT Claims Builder.
 * 
 * <p>
 * JwtClaimsBuilder implementations must set the 'iat' (issued at time), 'exp' (expiration time)
 * and 'jit' (unique token identifier) claims unless they have already been set.
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
     * Set an expiry 'exp' claim
     * 
     * @param expiredAt the expiry time
     * @return JwtClaimsBuilder
     */
    JwtClaimsBuilder expiresAt(long expiredAt);

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
     * Set a custom claim. Claim value is converted to String unless it is
     * an instance of {@link Boolean}, {@link Number}, {@link Collection}, {@link Map},
     * {@link JsonObject} or {@link JsonArray}.
     * 
     * @param name the claim name
     * @param value the claim value
     * @return JwtClaimsBuilder
     */
    JwtClaimsBuilder claim(String name, Object value);

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
