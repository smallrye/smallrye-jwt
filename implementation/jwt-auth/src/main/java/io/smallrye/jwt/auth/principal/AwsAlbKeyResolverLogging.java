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

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 14001, value = "mp.jwt.verify.publickey.algorithm is not set."
            + "Falling back to default algorithm: RS256 which is not compabible with AWS ALB."
            + "Please set mp.jwt.verify.publickey.algorithm to ES256")
    void publicKeyAlgorithmNotSet();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 14002, value = "mp.jwt.verify.publickey.algorithm is not set to ES256")
    void publicKeyAlgorithmNotSetToES256();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 14003, value = "mp.jwt.token.header is not set to X-Amzn-Oidc-Data")
    void invalidAWSTokenHeader();

}
