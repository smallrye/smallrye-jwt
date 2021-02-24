package io.smallrye.jwt.util;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import org.jboss.logging.Messages;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageBundle;

@MessageBundle(projectCode = "SRJWT", length = 5)
interface JWTUtilMessages {
    JWTUtilMessages msg = Messages.getBundle(JWTUtilMessages.class);

    @Message(id = 0, value = "Failed to decode the JWKS Public Key")
    UncheckedIOException invalidJWKSPublicKey(@Cause IOException ioe);

    @Message(id = 1, value = "Unsupported key type %s")
    NoSuchAlgorithmException unsupportedAlgorithm(String algorithmName);

    @Message(id = 2, value = "No resource with the named %s location exists")
    IOException keyNotFound(String keyLocation);

    @Message(id = 3, value = "Algorithm %s is not a symmetric-key algorithm")
    InvalidAlgorithmParameterException requiresSymmetricAlgo(String algorithmName);
}
