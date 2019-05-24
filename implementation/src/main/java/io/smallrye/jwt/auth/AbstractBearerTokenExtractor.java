package io.smallrye.jwt.auth;

import java.util.function.Function;

import javax.inject.Inject;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.logging.Logger;

import io.smallrye.jwt.auth.cdi.PrincipalProducer;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipal;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipalFactory;
import io.smallrye.jwt.auth.principal.ParseException;

/**
 * Common functionality for classes extracting Bearer tokens from HTTP request
 * headers (including Cookie) and converting the token string to a
 * {@link JsonWebToken}.
 *
 *
 * @author Michael Edgar {@literal <michael@xlate.io>}
 */
public abstract class AbstractBearerTokenExtractor {

    private static Logger logger = Logger.getLogger(AbstractBearerTokenExtractor.class);

    @Inject
    private JWTAuthContextInfo authContextInfo;

    @Inject
    private PrincipalProducer producer;

    protected JsonWebToken parseToken(String bearerToken) throws ParseException {
        JsonWebToken jwtPrincipal = validate(bearerToken);
        producer.setJsonWebToken(jwtPrincipal);
        return jwtPrincipal;
    }

    /**
     * Find a JWT Bearer token in the request by referencing the configurations
     * found in the {@link JWTAuthContextInfo}. The resulting token may be found
     * in a cookie or another HTTP header, either explicitly configured or the
     * default 'Authorization' header.
     *
     * @param headerExtractor
     *            function to retrieve an HTTP header by name
     * @param cookieValueExtractor
     *            function to retrieve an HTTP cookie value provided the name of
     *            the cookie
     * @return a JWT Bearer token or null if not found
     */
    protected String getBearerToken(Function<String, String> headerExtractor,
                                    Function<String, String> cookieValueExtractor) {

        final String tokenHeaderName = authContextInfo.getTokenHeader();
        final String bearerValue;

        if ("Cookie".equals(tokenHeaderName)) {
            String tokenCookieName = authContextInfo.getTokenCookie();

            if (tokenCookieName == null) {
                tokenCookieName = "Bearer";
            }

            logger.debugf("tokenCookieName = %s", tokenCookieName);

            bearerValue = cookieValueExtractor.apply(tokenCookieName);

            if (bearerValue == null) {
                logger.debugf("Cookie %s was null", tokenCookieName);
            }
        } else {
            final String tokenHeader = headerExtractor.apply(tokenHeaderName);
            logger.debugf("tokenHeaderName = %s", tokenHeaderName);

            if (tokenHeader != null && tokenHeader.startsWith("Bearer ")) {
                bearerValue = tokenHeader.substring("Bearer ".length());
            } else {
                logger.debugf("Header %s was null", tokenHeaderName);
                bearerValue = null;
            }
        }

        return bearerValue;
    }

    private JsonWebToken validate(String bearerToken) throws ParseException {
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JWTCallerPrincipal callerPrincipal = factory.parse(bearerToken, authContextInfo);
        return callerPrincipal;
    }
}
