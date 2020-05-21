package io.smallrye.jwt.config;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;

@MessageLogger(projectCode = "SRJWT", length = 5)
public interface ConfigLogging extends BasicLogger {
    ConfigLogging log = Logger.getMessageLogger(ConfigLogging.class, ConfigLogging.class.getPackage().getName());

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 3000, value = "init, mpJwtPublicKey=%s, mpJwtIssuer=%s, mpJwtLocation=%s")
    void configValues(String jwtPublicKey, String jwtIssuer, String jwtLocation);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 3001, value = "Neither mpJwtPublicKey nor mpJwtLocation properties are configured,"
            + " JWTAuthContextInfo will not be available")
    void publicKeyAndLocationAreUnavailable();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 3002, value = "mpJwtPublicKey parsed as JWK(S)")
    void publicKeyParsedAsJwk();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 3003, value = "mpJwtPublicKey failed as JWK(S), %s")
    void parsingPublicKeyAsJwkFailed(String exceptionMessage);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 3004, value = "mpJwtPublicKey parsed as PEM")
    void publicKeyParsedAsPem();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 3005, value = "Unsupported key format")
    void unsupportedKeyFormat();

    @LogMessage(level = Logger.Level.WARN)
    @Message(id = 3006, value = "'%s' property is deprecated and will be removed in a future version. " +
            "Use '%s ' property instead")
    void replacedConfig(String originalConfig, String newConfig);
}
