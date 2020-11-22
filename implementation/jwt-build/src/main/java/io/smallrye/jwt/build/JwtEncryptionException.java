package io.smallrye.jwt.build;

/**
 * JWT Encryption Exception
 */
@SuppressWarnings("serial")
public class JwtEncryptionException extends JwtException {
    public JwtEncryptionException() {
    }

    public JwtEncryptionException(String errorMessage) {
        super(errorMessage);
    }

    public JwtEncryptionException(Throwable t) {
        super(t);
    }

    public JwtEncryptionException(String errorMessage, Throwable t) {
        super(errorMessage, t);
    }
}
