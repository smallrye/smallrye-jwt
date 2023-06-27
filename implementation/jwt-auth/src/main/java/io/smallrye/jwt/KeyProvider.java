package io.smallrye.jwt;

/**
 * Well-known key providers.
 */
public enum KeyProvider {
    /**
     * AWS Application Load Balancer.
     *
     * Verification key in PEM format is fetched from the URI which is created by
     * adding the current token `kid` (key identifier) header value to the AWS ALB URI.
     */
    AWS_ALB,

    /**
     * Verification key is resolved as required by the MP JWT specification:
     * PEM or JWK key or JWK key set can be read from the local file system or fetched from URIs.
     */
    DEFAULT
}
