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

    @Message(id = 7002, value = "Failed to load a key from the 'mp.jwt.verify.publickey' property")
    UnresolvableKeyException failedToLoadPublicKey(@Cause Throwable throwable);

    @Message(id = 7003, value = "Failed to load a key from %s")
    UnresolvableKeyException failedToLoadPublicKeyFromLocation(@Pos(1) String location, @Cause Throwable throwable);

    @Message(id = 7004, value = "Failed to load a key from the 'mp.jwt.verify.publickey' property while resolving")
    UnresolvableKeyException failedToLoadPublicKeyWhileResolving();

    @Message(id = 7005, value = "Failed to load a key from %s property while resolving")
    UnresolvableKeyException failedToLoadPublicKeyFromLocationWhileResolving(@Pos(1) String location);

    @Message(id = 7006, value = "Invalid token 'kid' header")
    UnresolvableKeyException invalidTokenKid();

    @Message(id = 7007, value = "No resource with the named %s location exists")
    IOException resourceNotFound(String resourceName);

    @Message(id = 7008, value = "Failed to verify max TTL")
    ParseException failedToVerifyMaxTTL(@Cause Throwable throwable);

    @Message(id = 7009, value = "The Expiration Time (exp=%s) claim value cannot be more than %d"
            + " minutes in the future relative to Issued At (iat=%s)")
    ParseException expExceeded(NumericDate exp, long maxTimeToLiveSecs, NumericDate iat);

    @Message(id = 7010, value = "Required claims are not present in the JWT")
    InvalidJwtException missingClaims(@Producer Function<String, InvalidJwtException> fn);

    @Message(id = 7011, value = "Key is unresolvable")
    ParseException keyUnresolvable();

    @Message(id = 7012, value = "Encrypted token sequence is invalid")
    ParseException encryptedTokenSequenceInvalid();
}
