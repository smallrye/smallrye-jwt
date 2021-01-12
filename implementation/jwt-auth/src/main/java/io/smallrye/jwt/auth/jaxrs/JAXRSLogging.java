package io.smallrye.jwt.auth.jaxrs;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;

@MessageLogger(projectCode = "SRJWT", length = 5)
interface JAXRSLogging extends BasicLogger {
    JAXRSLogging log = Logger.getMessageLogger(JAXRSLogging.class, JAXRSLogging.class.getPackage().getName());

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 10000, value = "Success")
    void success();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 10001, value = "Unable to validate bearer token")
    void unableToValidateBearerToken(@Cause Throwable throwable);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 10002, value = "Failed to resolve the key. Either corrupt or unavailable.")
    void noUsableKey();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 10003, value = "EE Security is not in use, %s has been registered")
    void eeSecurityNotInUseButRegistered(String authenticationFilterName);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 10004, value = "MP-JWT LoginConfig present, %s is enabled")
    void mpJWTLoginConfigPresent(String className);

    @LogMessage(level = Logger.Level.INFO)
    @Message(id = 10005, value = "LoginConfig not found on Application class, %s will not be enabled")
    void mpJWTLoginConfigNotFound(String className);
}
