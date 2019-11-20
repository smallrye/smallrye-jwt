package io.smallrye.jwt.build;

/**
 * JWT Headers Builder.
 * <p>
 * JwtHeadersBuilder implementations should set the 'alg' (signing algorithm) to 'RS256' and 'typ' (token type) to 'JWT'
 * unless they have been already set by the users.
 * <p>
 * Note that the implementations are not required to be thread-safe.
 */
public interface JwtHeadersBuilder extends JwtSigner {

    /**
     * Set a 'kid' key id header
     * 
     * @param keyId the key id
     * @return JwtHeadersBuilder
     */
    JwtHeadersBuilder keyId(String keyId);

    /**
     * Custom JWT header
     * 
     * @param name the header name
     * @param value the header value
     * @return JwtHeadersBuilder
     */
    JwtHeadersBuilder header(String name, Object value);
}
