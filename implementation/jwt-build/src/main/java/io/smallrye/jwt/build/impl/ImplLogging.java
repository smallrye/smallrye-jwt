package io.smallrye.jwt.build.impl;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;

@MessageLogger(projectCode = "SRJWT", length = 5)
interface ImplLogging extends BasicLogger {
    ImplLogging log = Logger.getMessageLogger(ImplLogging.class, ImplLogging.class.getPackage().getName());

    @LogMessage(level = Logger.Level.WARN)
    @Message(id = 1000, value = "%s property is deprecated and will be removed in the next major release")
    void deprecatedProperty(String property);

    @LogMessage(level = Logger.Level.WARN)
    @Message(id = 1001, value = "Inner-sign none signature mode is deprecated and will be removed in the next major release")
    void deprecatedInnerSignNone();
}
