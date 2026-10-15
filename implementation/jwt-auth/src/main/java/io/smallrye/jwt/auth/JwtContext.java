package io.smallrye.jwt.auth;

import io.smallrye.jwt.common.JwtClaims;

/**
 * The result of a successful token verification: the verified claims and the token type
 * recorded in the JOSE {@code typ} header, if any.
 *
 * @param tokenType the {@code typ} JOSE header value, may be null
 * @param claims the verified token claims
 */
public record JwtContext(String tokenType, JwtClaims claims) {
}
