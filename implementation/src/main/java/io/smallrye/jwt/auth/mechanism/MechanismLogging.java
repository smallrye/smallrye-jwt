package io.smallrye.jwt.auth.mechanism;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;

@MessageLogger(projectCode = "SRJWT", length = 5)
interface MechanismLogging extends BasicLogger {
    MechanismLogging log = Logger.getMessageLogger(MechanismLogging.class, MechanismLogging.class.getPackage().getName());

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 11000, value = "Success")
    void success();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 11001, value = "Unable to validate bearer token")
    void unableToValidateBearerToken(@Cause Throwable throwable);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 11002, value = "No usable bearer token was found in the request, continuing unauthenticated")
    void noUsableBearerTokenFound();
}