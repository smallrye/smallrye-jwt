package io.smallrye.jwt.build.spi;

import org.jboss.logging.Messages;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageBundle;

import io.smallrye.jwt.build.JwtException;

@MessageBundle(projectCode = "SRJWT", length = 5)
interface SpiMessages {
    SpiMessages msg = Messages.getBundle(SpiMessages.class);

    @Message(id = 4000, value = "JwtProvider %s has not been found: %s")
    JwtException providerNotFound(String provider, String exceptionMessage, @Cause Throwable throwable);

    @Message(id = 4001, value = "JwtProvider %s class could not be accessed: %s")
    JwtException providerClassCannotBeAccessed(String provider, String exceptionMessage, @Cause Throwable throwable);

    @Message(id = 4002, value = "JwtProvider %s could not be instantiated: %s")
    JwtException providerCannotBeInstantiated(String provider, String exceptionMessage, @Cause Throwable throwable);
}
