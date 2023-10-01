package io.smallrye.jwt.auth.principal;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;

@MessageLogger(projectCode = "SRJWT", length = 5)
interface AwsAlbKeyResolverLogging extends BasicLogger {
    AwsAlbKeyResolverLogging log = Logger.getMessageLogger(AwsAlbKeyResolverLogging.class,
            AwsAlbKeyResolverLogging.class.getPackage().getName());

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 14000, value = "public key path: %s")
    void publicKeyPath(String path);

}
