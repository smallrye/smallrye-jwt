package io.smallrye.jwt.config;

import javax.enterprise.inject.spi.DeploymentException;

import org.jboss.logging.Messages;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageBundle;

@MessageBundle(projectCode = "SRJWT", length = 5)
interface ConfigMessages {
    ConfigMessages msg = Messages.getBundle(ConfigMessages.class);

    @Message(id = 2000, value = "HS256 verification algorithm is currently not supported")
    DeploymentException hs256NotSupported();

    @Message(id = 2001, value = "Failed to decode the MP JWT Public Key")
    DeploymentException parsingPublicKeyFailed(@Cause Throwable throwable);

    @Message(id = 2002, value = "JWTAuthContextInfo has not been initialized. Please make sure that either "
            + "'mp.jwt.verify.publickey' or 'mp.jwt.verify.publickey.location' properties are set.")
    IllegalStateException authContextHasNotBeenInitialized();
}
