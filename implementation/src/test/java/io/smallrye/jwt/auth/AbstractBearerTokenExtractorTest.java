package io.smallrye.jwt.auth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.when;

import java.util.function.Function;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;

public class AbstractBearerTokenExtractorTest {

    private static final String AUTHORIZATION = "Authorization";
    private static final String COOKIE = "Cookie";

    @Mock
    JWTAuthContextInfo authContextInfo;

    AbstractBearerTokenExtractor target;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
    }

    private AbstractBearerTokenExtractor newTarget(Function<String, String> headerValue,
                                                   Function<String, String> cookieValue) {
        return new AbstractBearerTokenExtractor(authContextInfo) {
            @Override
            protected String getHeaderValue(String headerName) {
                return headerValue.apply(headerName);
            }
            @Override
            protected String getCookieValue(String cookieName) {
                return cookieValue.apply(cookieName);
            }
        };
    }

    @Test
    public void testGetBearerTokenAuthorizationHeader() {
        when(authContextInfo.getTokenHeader()).thenReturn(AUTHORIZATION);
        AbstractBearerTokenExtractor target = newTarget(h ->"Bearer THE_TOKEN", c -> null);
        String bearerToken = target.getBearerToken();
        assertEquals("THE_TOKEN", bearerToken);
    }

    @Test
    public void testGetBearerTokenMissingAuthorizationHeader() {
        when(authContextInfo.getTokenHeader()).thenReturn(AUTHORIZATION);
        AbstractBearerTokenExtractor target = newTarget(h -> null, c -> null);
        String bearerToken = target.getBearerToken();
        assertNull(bearerToken);
    }

    @Test
    public void testGetBearerTokenOtherSchemeAuthorizationHeader() {
        when(authContextInfo.getTokenHeader()).thenReturn(AUTHORIZATION);
        AbstractBearerTokenExtractor target = newTarget(h -> "Basic Not_a_JWT", c -> null);
        String bearerToken = target.getBearerToken();
        assertNull(bearerToken);
    }

    @Test
    public void testGetBearerTokenDefaultCookieHeader() {
        when(authContextInfo.getTokenHeader()).thenReturn(COOKIE);
        AbstractBearerTokenExtractor target = newTarget(h -> null, c -> "THE_TOKEN");
        String bearerToken = target.getBearerToken();
        assertEquals("THE_TOKEN", bearerToken);
    }

    @Test
    public void testGetBearerTokenCustomCookieHeader() {
        when(authContextInfo.getTokenHeader()).thenReturn(COOKIE);
        when(authContextInfo.getTokenCookie()).thenReturn("CustomCookie");
        AbstractBearerTokenExtractor target = newTarget(h -> null, c -> {
            if ("CustomCookie".equals(c)) {
                return "THE_TOKEN";
            }
            return null;
        });
        String bearerToken = target.getBearerToken();
        assertEquals("THE_TOKEN", bearerToken);
    }

    @Test
    public void testGetBearerTokenMissingCookieHeader() {
        when(authContextInfo.getTokenHeader()).thenReturn(COOKIE);
        AbstractBearerTokenExtractor target = newTarget(h -> null, c -> null);
        String bearerToken = target.getBearerToken();
        assertNull(bearerToken);
    }
}
