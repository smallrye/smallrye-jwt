package io.smallrye.jwt.auth.principal;

import java.io.IOException;
import java.util.function.Function;

import org.jboss.logging.Messages;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageBundle;
import org.jboss.logging.annotations.Pos;
import org.jboss.logging.annotations.Producer;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.UnresolvableKeyException;

@MessageBundle(projectCode = "SRJWT", length = 5)
interface PrincipalMessages {
    PrincipalMessages msg = Messages.getBundle(PrincipalMessages.class);

    @Message(id = 7000, value = "Failed to verify a token")
    ParseException failedToVerifyToken(@Cause Throwable throwable);

    @Message(id = 7001, value = "No claim exists in sub, upn or preferred_username")
    InvalidJwtException claimNotFound(@Producer Function<String, InvalidJwtException> fn);

    @Message(id = 7002, value = "Failed to load a key from the key content")
    UnresolvableKeyException failedToLoadKey(@Cause Throwable throwable);

    @Message(id = 7003, value = "Failed to load a key from %s")
    UnresolvableKeyException failedToLoadKeyFromLocation(@Pos(1) String location, @Cause Throwable throwable);

    @Message(id = 7004, value = "Failed to load a key from the key content while resolving")
    UnresolvableKeyException failedToLoadKeyWhileResolving();

    @Message(id = 7005, value = "Failed to load a key from %s property while resolving")
    UnresolvableKeyException failedToLoadKeyFromLocationWhileResolving(@Pos(1) String location);

    @Message(id = 7006, value = "Invalid token 'kid' header")
    UnresolvableKeyException invalidTokenKid();

    @Message(id = 7007, value = "No resource with the named %s location exists")
    IOException resourceNotFound(String resourceName);

    @Message(id = 7008, value = "Invalid 'iat' or 'exp' claim value")
    ParseException invalidIatExp();

    @Message(id = 7009, value = "The Expiration Time (exp=%s) claim value cannot be more than %d"
            + " seconds in the future relative to Issued At (iat=%s) claim value")
    ParseException expExceeded(NumericDate exp, long maxTimeToLiveSecs, NumericDate iat);

    @Message(id = 7010, value = "Required claims are not present in the JWT")
    InvalidJwtException missingClaims(@Producer Function<String, InvalidJwtException> fn);

    @Message(id = 7011, value = "Verification key is unresolvable")
    ParseException verificationKeyUnresolvable();

    @Message(id = 7012, value = "Decryption key is unresolvable")
    ParseException decryptionKeyUnresolvable();

    @Message(id = 7013, value = "Encrypted token sequence is invalid")
    ParseException encryptedTokenSequenceInvalid();

    @Message(id = 7014, value = "Failed to load X509 certificates")
    ParseException failedToLoadCertificates();

    @Message(id = 7015, value = "The Expiration Time (exp=%s) claim value cannot be less than Issued At (iat=%s) claim value")
    ParseException failedToVerifyIatExp(NumericDate exp, NumericDate iat);
}
