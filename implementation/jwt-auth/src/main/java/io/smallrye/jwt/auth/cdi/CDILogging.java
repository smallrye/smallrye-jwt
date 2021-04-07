package io.smallrye.jwt.auth.cdi;

import java.util.Optional;

import javax.enterprise.inject.spi.Annotated;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.InjectionPoint;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;

@MessageLogger(projectCode = "SRJWT", length = 5)
interface CDILogging extends BasicLogger {
    CDILogging log = Logger.getMessageLogger(CDILogging.class, CDILogging.class.getPackage().getName());

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 12000, value = "getValue(%s), null JsonWebToken")
    void getValue(String name);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 12001, value = "Failed to find Claim for: %s")
    void failedToFindClaim(String name);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 12002, value = "getValue(%s), isOptional=%s, claimValue=%s")
    void getValueResult(String name, boolean isOptional, Optional claimValue);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 12003, value = "JsonValueProducer(%s).produce")
    void jsonValueProducer(InjectionPoint injectionPoint);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 12004, value = "getOptionalString(%s)")
    void getOptionalString(InjectionPoint injectionPoint);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 12005, value = "getOptionalStringSet(%s)")
    void getOptionalStringSet(InjectionPoint injectionPoint);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 12006, value = "getOptionalLong(%s)")
    void getOptionalLong(InjectionPoint injectionPoint);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 12007, value = "getOptionalBoolean(%s)")
    void getOptionalBoolean(InjectionPoint injectionPoint);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 12008, value = "addTypeToClaimProducer(%s)")
    void addTypeToClaimProducer(Annotated annotated);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 12009, value = "Checking Provider Claim(%s), ip: %s")
    void checkingProviderClaim(String claimName, InjectionPoint injectionPoint);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 12010, value = "pip: %s")
    void pip(InjectionPoint injectionPoint);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 12011, value = "getClaimAsSet(%s)")
    void getClaimAsSet(InjectionPoint injectionPoint);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 12012, value = "getClaimAsString(%s)")
    void getClaimAsString(InjectionPoint injectionPoint);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 12013, value = "getClaimAsLong(%s)")
    void getClaimAsLong(InjectionPoint injectionPoint);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 12014, value = "getClaimAsDouble(%s)")
    void getClaimAsDouble(InjectionPoint injectionPoint);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 12015, value = "getClaimAsBoolean(%s)")
    void getClaimAsBoolean(InjectionPoint injectionPoint);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 12016, value = "getOptionalValue(%s)")
    void getOptionalValue(InjectionPoint injectionPoint);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 12017, value = "beforeBeanDiscovery(%s)")
    void beforeBeanDiscovery(BeanManager beanManager);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 12018, value = "EE Security is available, JWTHttpAuthenticationMechanism has been registered")
    void jwtHttpAuthenticationMechanismRegistered();

    @LogMessage(level = Logger.Level.INFO)
    @Message(id = 12019, value = "EE Security is NOT available, JWTAuthenticationFilter has been registered")
    void jwtHttpAuthenticationMechanismNotRegistered();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 12020, value = "Added type: %s")
    void addedType(String name);
}
