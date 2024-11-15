package io.smallrye.jwt.auth.principal;

import java.net.URL;
import java.util.List;
import java.util.ServiceLoader;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;

@MessageLogger(projectCode = "SRJWT", length = 5)
interface PrincipalLogging extends BasicLogger {
    PrincipalLogging log = Logger.getMessageLogger(PrincipalLogging.class, PrincipalLogging.class.getPackage().getName());

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8000, value = "getAudience failure")
    void getAudienceFailure(@Cause Throwable throwable);

    @LogMessage(level = Logger.Level.WARN)
    @Message(id = 8001, value = "getGroups failure: ")
    void getGroupsFailure(@Cause Throwable throwable);

    @LogMessage(level = Logger.Level.WARN)
    @Message(id = 8002, value = "getClaimValue failure for: %s")
    void getGroupsFailure(String claimName, @Cause Throwable throwable);

    @LogMessage(level = Logger.Level.WARN)
    @Message(id = 8003, value = "replaceClaimValueWithJsonValue failure for: %s")
    void replaceClaimValueWithJsonFailure(String claimName, @Cause Throwable throwable);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8004, value = "Token is invalid")
    void tokenInvalid();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8005, value = "Verification key is unresolvable")
    void verificationKeyUnresolvable();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8006, value = "Claim value at the path %s is not a String")
    void claimAtPathIsNotAString(String claimPath);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8007, value = "Claim value at the path %s is not an array of strings")
    void claimAtPathIsNotAnArrayOfStrings(String claimPath);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8008, value = "Claim value at the path %s is neither an array of strings nor string")
    void claimAtPathIsNeitherAnArrayOfStringsNorString(String claimPath);

    @LogMessage(level = Logger.Level.TRACE)
    @Message(id = 8009, value = "Updated groups to: %s")
    void updatedGroups(List<String> groups);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8010, value = "Failed to access rolesMapping claim")
    void failedToAccessRolesMappingClaim(@Cause Throwable throwable);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8011, value = "No claim exists at the path %s at segment %s")
    void claimNotFoundAtPathAtSegment(String claimPath, String segment);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8012, value = "Claim value at the path %s is not a json object")
    void claimValueIsNotAJson(String claimPath);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8014, value = "Required claims %s are not present in the JWT")
    void missingClaims(String missingClaims);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8015, value = "loadSpi, cl=%s, u=%s, sl=%s")
    void loadSpi(ClassLoader classLoader, URL url, ServiceLoader<JWTCallerPrincipalFactory> serviceLoader);

    @LogMessage(level = Logger.Level.WARN)
    @Message(id = 8016, value = "Multiple JWTCallerPrincipalFactory implementations found: %s and %s")
    void multipleJWTCallerPrincipalFactoryFound(String instanceName1, String instanceName2);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8017, value = "sl=%s, loaded=%s")
    void currentSpi(ServiceLoader<JWTCallerPrincipalFactory> sl, JWTCallerPrincipalFactory spi);

    @LogMessage(level = Logger.Level.WARN)
    @Message(id = 8018, value = "Failed to locate JWTCallerPrincipalFactory provider")
    void failedToLocateJWTCallerPrincipalFactoryProvider(@Cause Throwable throwable);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8019, value = "AuthContextInfo is: %s")
    void authContextInfo(JWTAuthContextInfo authContextInfo);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8020, value = "Failed to create a key from the HTTPS JWK Set")
    void failedToCreateKeyFromJWKSet(@Cause Throwable throwable);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8021, value = "JWK with a matching 'kid' is not available, refreshing HTTPS JWK Set")
    void kidIsNotAvailableRefreshingJWKSet();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8022, value = "Failed to refresh HTTPS JWK Set")
    void failedToRefreshJWKSet(@Cause Throwable throwable);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8023, value = "JWK with a matching 'kid' is not available but HTTPS JWK Set has " +
            "been refreshed less than %d minutes ago, trying to create a key from the HTTPS JWK Set one " +
            "more time")
    void matchingKidIsNotAvailableButJWTSRefreshed(int minutes);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8024, value = "Trying to create a key from the HTTPS JWK Set after the refresh")
    void tryCreateKeyFromJWKSAfterRefresh();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8025, value = "Failed to create a key from the HTTPS JWK Set after the refresh")
    void failedToCreateKeyFromJWKSAfterRefresh(@Cause Throwable throwable);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8026, value = "Trying to create a key from the JWK(S)")
    void tryCreateKeyFromJWKS();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8027, value = "Failed to create a key from the JWK(S)")
    void failedToCreateKeyFromJWKS(@Cause Throwable throwable);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8028, value = "Invalid token 'kid' header: %s, expected: %s")
    void invalidTokenKidHeader(String kidHeaderName, String expectedName);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8029, value = "Trying to load the keys from the HTTPS JWK(S)")
    void tryLoadKeyFromJWKS();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8030, value = "Checking if the key content is a JWK key or JWK key set")
    void checkKeyContentIsJWKKeyOrJWKKeySet();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8031, value = "Checking if the key content is a Base64URL encoded JWK key or JWK key set")
    void checkKeyContentIsBase64EncodedJWKKeyOrJWKKeySet();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8032, value = "Unable to decode content using Base64 decoder")
    void unableToDecodeContentUsingBase64(@Cause Throwable throwable);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8033, value = "Key has been created from the encoded JWK key or JWK key set")
    void keyCreatedFromEncodedJWKKeyOrJWKKeySet();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8034, value = "Key has been created from the JWK key or JWK key set")
    void keyCreatedFromJWKKeyOrJWKKeySet();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8035, value = "Checking if the key content is a Base64 encoded PEM key")
    void checkKeyContentIsBase64EncodedPEMKey();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8036, value = "Key has been created from the encoded PEM key")
    void keyCreatedFromEncodedPEMKey();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8037, value = "The key content is not a valid encoded PEM key")
    void keyContentIsNotValidEncodedPEMKey(@Cause Throwable throwable);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8038, value = "Checking if the key content is a Base64 encoded PEM certificate")
    void checkKeyContentIsBase64EncodedPEMCertificate();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8039, value = "PublicKey has been created from the encoded PEM certificate")
    void publicKeyCreatedFromEncodedPEMCertificate();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8040, value = "The key content is not a valid encoded PEM certificate")
    void keyContentIsNotValidEncodedPEMCertificate(@Cause Throwable throwable);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8041, value = "Decryption key is unresolvable")
    void decryptionKeyUnresolvable();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8042, value = "Encrypted token sequence is invalid")
    void encryptedTokenSequenceInvalid();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8043, value = "Trying to create a key from the HTTPS JWK(S)")
    void tryCreateKeyFromHttpsJWKS();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8044, value = "Encrypted token headers must contain a content type header")
    void encryptedTokenMissingContentType();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 8045, value = "Claim %s's value type is expected to be %s but it is %s")
    void claimTypeMismatch(String claimName, String expectedType, String actualType);

}
