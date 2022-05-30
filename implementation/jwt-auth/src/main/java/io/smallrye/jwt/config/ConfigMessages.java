package io.smallrye.jwt.config;

import jakarta.enterprise.inject.spi.DeploymentException;

import org.jboss.logging.Messages;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageBundle;

@MessageBundle(projectCode = "SRJWT", length = 5)
interface ConfigMessages {
    ConfigMessages msg = Messages.getBundle(ConfigMessages.class);

    @Message(id = 2000, value = "HMAC verification algorithms are not supported when the 'mp.jwt.verify.publickey.location' property is set, use 'smallrye.jwt.verify.key.location' instead")
    DeploymentException hmacNotSupported();

    @Message(id = 2001, value = "Failed to decode the MP JWT Public Key")
    DeploymentException parsingPublicKeyFailed(@Cause Throwable throwable);

    @Message(id = 2002, value = "Failed to read the public key content from 'mp.jwt.verify.publickey.location'")
    DeploymentException readingPublicKeyLocationFailed(@Cause Throwable throwable);

    @Message(id = 2003, value = "'mp.jwt.verify.publickey.location' is invalid")
    DeploymentException invalidPublicKeyLocation();

    @Message(id = 2004, value = "Failed to read the decryption key content from 'smallrye.jwt.decrypt.key.location'")
    DeploymentException readingDecryptKeyLocationFailed(@Cause Throwable throwable);

    @Message(id = 2005, value = "'smallrye.jwt.decrypt.key.location' is invalid")
    DeploymentException invalidDecryptKeyLocation();
}
