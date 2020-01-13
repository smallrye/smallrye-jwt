package io.smallrye.jwt.build;

/**
 * JWT Signature Exception
 */
@SuppressWarnings("serial")
public class JwtSignatureException extends JwtException {
    public JwtSignatureException() {
    }

    public JwtSignatureException(String errorMessage) {
        super(errorMessage);
    }

    public JwtSignatureException(Throwable t) {
        super(t);
    }

    public JwtSignatureException(String errorMessage, Throwable t) {
        super(errorMessage, t);
    }
}
