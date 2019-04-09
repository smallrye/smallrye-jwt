package io.smallrye.jwt.auth.principal;


import org.jose4j.jwt.consumer.JwtContext;

/**
 * A default implementation of the abstract JWTCallerPrincipalFactory that uses the Keycloak token parsing classes.
 */
public class DefaultJWTCallerPrincipalFactory extends JWTCallerPrincipalFactory {
    
    private DefaultJWTTokenParser parser = new DefaultJWTTokenParser();

    /**
     * Tries to load the JWTAuthContextInfo from CDI if the class level authContextInfo has not been set.
     */
    public DefaultJWTCallerPrincipalFactory() {
    }

    @Override
    public JWTCallerPrincipal parse(final String token, final JWTAuthContextInfo authContextInfo) throws ParseException {

        JwtContext jwtContext = parser.parse(token, authContextInfo);
        String type = jwtContext.getJoseObjects().get(0).getHeader("typ");
        return new DefaultJWTCallerPrincipal(type, jwtContext.getJwtClaims());
    }
    
}
