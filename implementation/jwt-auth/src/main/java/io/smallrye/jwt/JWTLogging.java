package io.smallrye.jwt;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;

@MessageLogger(projectCode = "SRJWT", length = 5)
interface JWTLogging extends BasicLogger {
    JWTLogging log = Logger.getMessageLogger(JWTLogging.class, JWTLogging.class.getPackage().getName());

    @LogMessage(level = Logger.Level.ERROR)
    @Message(id = 1000, value = "path.%s configuration will be ignored because the path depth is too large:"
            + " %d, maximum depth is %d.")
    void maximumPathDepthReached(String claimName, Object pathDepth, Object maxPathDepthSupported);

    @LogMessage(level = Logger.Level.ERROR)
    @Message(id = 1001, value = "Token header is not 'Cookie', the cookie name value will be ignored")
    void tokenHeaderIsNotCookieHeader();

    @LogMessage(level = Logger.Level.ERROR)
    @Message(id = 1002, value = "Algorithm %s not supported")
    void unsupportedAlgorithm(String unsupportedAlgorithm);
}
