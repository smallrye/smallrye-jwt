package io.smallrye.jwt.auth.dpop;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;

@MessageLogger(projectCode = "SRJWT", length = 5)
interface DpopLogging extends BasicLogger {
    DpopLogging log = Logger.getMessageLogger(DpopLogging.class, DpopLogging.class.getPackage().getName());

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 15000, value = "Invalid DPoP token")
    void invalidDpopToken();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 15001, value = "Missing DPoP token")
    void missingDpopToken();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 15002, value = "Missing DPoP key binding in access token")
    void missingDpopKeyBinding();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 15003, value = "Invalid request URL: %s")
    void invalidRequestUrl(String invalidUrlMsg);
}
