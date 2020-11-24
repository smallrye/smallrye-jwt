package io.smallrye.jwt.auth.cdi;

import javax.enterprise.inject.spi.DeploymentException;
import javax.enterprise.inject.spi.InjectionPoint;

import org.jboss.logging.Messages;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageBundle;

@MessageBundle(projectCode = "SRJWT", length = 5)
interface CDIMessages {
    CDIMessages msg = Messages.getBundle(CDIMessages.class);

    @Message(id = 13000, value = "@Claim at: %s has no name or valid standard enum setting")
    DeploymentException claimHasNoNameOrValidStandardEnumSetting(InjectionPoint injectionPoint);
}
