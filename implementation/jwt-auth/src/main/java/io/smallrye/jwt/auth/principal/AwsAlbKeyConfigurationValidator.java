package io.smallrye.jwt.auth.principal;

import java.net.URI;

import org.jose4j.lang.UnresolvableKeyException;

import io.smallrye.jwt.algorithm.SignatureAlgorithm;

interface AwsAlbKeyConfigurationValidator {

    public static void validateKeyConfiguration(JWTAuthContextInfo authContextInfo) throws UnresolvableKeyException {
        // public key location check
        var publicKeyLocation = authContextInfo.getPublicKeyLocation();
        if (publicKeyLocation == null) {
            throw PrincipalMessages.msg.nullKeyLocation();
        }
        if (containsSubPath(publicKeyLocation)) {
            throw AwsAlbKeyResolverMessages.msg.subPathNotAllowed();
        }
    }

    public static void validatePublicKeyAlgorithmConfiguration(JWTAuthContextInfo authContextInfo) {
        var publicKeyAlgorithm = authContextInfo.getSignatureAlgorithm();
        if (publicKeyAlgorithm == null) {
            AwsAlbKeyResolverLogging.log.publicKeyAlgorithmNotSet();
        }
        if (!publicKeyAlgorithm.getAlgorithm().equals(SignatureAlgorithm.ES256.getAlgorithm())) {
            AwsAlbKeyResolverLogging.log.publicKeyAlgorithmNotSetToES256();
        }
    }

    /**
     * verifies the entry: <code>mp.jwt.token.header=X-Amzn-Oidc-Data</code>
     *
     * @param authContextInfo
     */
    public static void validateTokenHeaderConfiguration(JWTAuthContextInfo authContextInfo) {
        var tokenHeader = authContextInfo.getTokenHeader();
        if (tokenHeader == null || !"X-Amzn-Oidc-Data".equals(tokenHeader)) {
            AwsAlbKeyResolverLogging.log.invalidAWSTokenHeader();
        }

    }

    /**
     * Remove ending slash from uri e.g. https://localhost:8080/ ->
     * https://localhost:8080
     *
     * @param uri public key location
     * @return uri without ending slash
     */
    static String removeEndingSlash(String uri) {
        if (!uri.endsWith("/") || uri.length() == 1) {
            return uri;
        }
        var length = uri.length();
        return uri.substring(0, length - 1);
    }

    /**
     * Check if public key location contains sub path e.g.
     * https://localhost:8080/subpath
     * Fails fast to prevent runtime errors
     *
     * @param publicKeyLocation to check
     * @return true if public key location contains sub path which is invalid
     */
    static boolean containsSubPath(String publicKeyLocation) {
        var locationWithoutSlash = removeEndingSlash(publicKeyLocation);
        var uri = URI.create(locationWithoutSlash);
        return uri.getPath().contains("/");
    }

}
