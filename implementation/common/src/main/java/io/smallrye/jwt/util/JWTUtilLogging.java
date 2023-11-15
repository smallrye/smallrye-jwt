package io.smallrye.jwt.util;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;

@MessageLogger(projectCode = "SRJWT", length = 5)
interface JWTUtilLogging extends BasicLogger {
    JWTUtilLogging log = Logger.getMessageLogger(JWTUtilLogging.class, JWTUtilLogging.class.getPackage().getName());

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 1003, value = "Trying to create a key from the encoded PEM key...")
    void creatingKeyFromPemKey();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 1004, value = "Failed to create a key from the encoded PEM key")
    void creatingKeyFromPemKeyFailed(@Cause Throwable throwable);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 1005, value = "Trying to create a key from the encoded PEM certificate...")
    void creatingKeyFromPemCertificate();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 1006, value = "Failed to to create a key from the encoded PEM certificate")
    void creatingKeyFromPemCertificateFailed(@Cause Throwable throwable);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 1007, value = "Trying to load the local JWK(S)...")
    void loadingJwks();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 1008, value = "Failed to load the JWK(S)")
    void loadingJwksFailed(@Cause Throwable throwable);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 1009, value = "Failed to parse the JWK JSON representation")
    void parsingJwksFailed();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 1010, value = "File %s is not found")
    void fileIsNotFound(String fileLocation);
}