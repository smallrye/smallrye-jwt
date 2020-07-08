package io.smallrye.jwt.auth;

import org.jboss.logging.Messages;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageBundle;

import io.smallrye.jwt.auth.principal.ParseException;

@MessageBundle(projectCode = "SRJWT", length = 5)
interface AuthMessages {
    AuthMessages msg = Messages.getBundle(AuthMessages.class);

    @Message(id = 14000, value = "Failed to verify DPoP token")
    ParseException failedToVerifyDpopToken(@Cause Throwable e);

    @Message(id = 14001, value = "Missing DPoP proofing value")
    ParseException missingDpopProof();

    @Message(id = 14002, value = "Missing DPoP key binding")
    ParseException missingDpopKeyBinding();
}
