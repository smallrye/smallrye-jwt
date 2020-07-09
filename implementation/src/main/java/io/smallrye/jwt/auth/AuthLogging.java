package io.smallrye.jwt.auth;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;

@MessageLogger(projectCode = "SRJWT", length = 5)
interface AuthLogging extends BasicLogger {
    AuthLogging log = Logger.getMessageLogger(AuthLogging.class, AuthLogging.class.getPackage().getName());

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 6000, value = "tokenHeaderName = %s")
    void tokenHeaderName(String headerName);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 6001, value = "Header %s was null")
    void headerIsNull(String headerName);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 6002, value = "tokenCookieName = %s")
    void tokenCookieName(String cookieName);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 6003, value = "Cookie %s was null")
    void cookieIsNull(String cookieName);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 6004, value = "Authorization header does not contain a Bearer prefix")
    void authHeaderDoesNotContainBearerPrefix();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 6005, value = "Authorization header was null")
    void authHeaderIsNull();
}