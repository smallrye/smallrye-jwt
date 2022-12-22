package io.smallrye.jwt.build.impl;

import org.jboss.logging.Messages;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageBundle;

import io.smallrye.jwt.build.JwtEncryptionException;
import io.smallrye.jwt.build.JwtException;
import io.smallrye.jwt.build.JwtSignatureException;

@MessageBundle(projectCode = "SRJWT", length = 5)
interface ImplMessages {
    ImplMessages msg = Messages.getBundle(ImplMessages.class);

    @Message(id = 5000, value = "Unsupported signature algorithm: %s")
    JwtSignatureException unsupportedSignatureAlgorithm(String algorithmName,
            @Cause Throwable throwable);

    JwtSignatureException unsupportedSignatureAlgorithm(String algorithmName);

    @Message(id = 5003, value = "%s")
    JwtEncryptionException joseSerializationError(String errorMessage, @Cause Throwable t);

    @Message(id = 5004, value = "Direct content encryption is currently not supported")
    JwtEncryptionException directContentEncryptionUnsupported();

    @Message(id = 5005, value = "Unsupported key encryption algorithm: %s")
    JwtEncryptionException unsupportedKeyEncryptionAlgorithm(String algorithmName);

    @Message(id = 5006, value = "Unsupported content encryption algorithm: %s")
    JwtEncryptionException unsupportedContentEncryptionAlgorithm(String algorithmName);

    @Message(id = 5007, value = "Key encryption key can not be loaded from: %s")
    IllegalArgumentException encryptionKeyCanNotBeLoadedFromLocation(String keyLocation);

    @Message(id = 5008, value = "Please set 'smallrye.jwt.encrypt.key.location' or 'smallrye.jwt.encrypt.key' property")
    IllegalArgumentException encryptionKeyNotConfigured();

    @Message(id = 5009, value = "")
    JwtSignatureException signatureException(@Cause Throwable throwable);

    @Message(id = 5010, value = "Inner JWT can not be created, "
            + "'smallrye.jwt.sign.key.location' is not set but the 'alg' header is: %s")
    JwtSignatureException signKeyPropertyRequired(String algorithmName);

    @Message(id = 5011, value = "None signature algorithm is currently not supported")
    JwtSignatureException noneSignatureAlgorithmUnsupported();

    @Message(id = 5012, value = "Failure to create a signed JWT token: %s")
    JwtSignatureException signJwtTokenFailed(String exceptionMessage, @Cause Throwable throwable);

    @Message(id = 5013, value = "JWK algorithm 'alg' value does not match a key type")
    IllegalArgumentException algDoesNotMatchKeyType();

    @Message(id = 5014, value = "Only PrivateKey or SecretKey can be be used to sign a token")
    IllegalArgumentException publicKeyBeingUsedForSign();

    @Message(id = 5015, value = "Failure to read the json content: %s")
    JwtException readJsonFailure(String exceptionMessage, @Cause Throwable throwable);

    @Message(id = 5016, value = "Failure to parse JWK: %s")
    JwtException failureToParseJWK(String exceptionMessage, @Cause Throwable throwable);

    @Message(id = 5017, value = "Failure to parse JWK Set: %s")
    JwtException failureToParseJWKS(String exceptionMessage, @Cause Throwable throwable);

    @Message(id = 5018, value = "Key id 'kid' header value must be provided")
    IllegalArgumentException kidRequired();

    @Message(id = 5019, value = "JWK set has no key with a key id 'kid' header '%s'")
    IllegalArgumentException keyWithKidNotFound(String keyId);

    @Message(id = 5020, value = "Signing key can not be loaded from: %s")
    IllegalArgumentException signingKeyCanNotBeLoadedFromLocation(String keyLocation, @Cause Throwable throwable);

    @Message(id = 5021, value = "Please set 'smallrye.jwt.sign.key.location' or 'smallrye.jwt.sign.key' property")
    IllegalArgumentException signKeyNotConfigured();

    @Message(id = 5022, value = "Failure to parse the JWT claims: %s")
    JwtException failureToParseJWTClaims(String exceptionMessage, @Cause Throwable throwable);

    @Message(id = 5024, value = "Failure to read the private key: %s")
    JwtException failureToReadPrivateKey(String exceptionMessage, @Cause Throwable throwable);

    @Message(id = 5025, value = "Failure to open the input stream from %s")
    JwtException failureToOpenInputStreamFromJsonResName(String jsonResName);

    @Message(id = 5026, value = "Failure to read the json content from %s: %s")
    JwtException failureToReadJsonContentFromJsonResName(String jsonResName, String exceptionMessage,
            @Cause Throwable throwable);

    @Message(id = 5027, value = "Failure to encrypt the token")
    JwtEncryptionException encryptionException(@Cause Throwable throwable);

    @Message(id = 5028, value = "Signing key can not be created from the loaded content")
    IllegalArgumentException signingKeyCanNotBeCreatedFromContent();

    @Message(id = 5029, value = "Encryption key can not be created from the loaded content")
    IllegalArgumentException encryptionKeyCanNotBeCreatedFromContent();

    @Message(id = 5030, value = "Signing key can not be read from the keystore")
    IllegalArgumentException signingKeyCanNotBeReadFromKeystore(@Cause Throwable throwable);

    @Message(id = 5031, value = "Encryption key can not be read from the keystore")
    IllegalArgumentException encryptionKeyCanNotBeReadFromKeystore(@Cause Throwable throwable);

    @Message(id = 5032, value = "Signing key is null")
    NullPointerException signingKeyIsNull();

    @Message(id = 5033, value = "Encryption key is null")
    NullPointerException encryptionKeyIsNull();
}
