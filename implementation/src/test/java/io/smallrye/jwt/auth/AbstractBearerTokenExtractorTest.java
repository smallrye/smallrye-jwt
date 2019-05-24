package io.smallrye.jwt.auth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.ext.RuntimeDelegate;
import javax.ws.rs.ext.RuntimeDelegate.HeaderDelegate;

import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;

public class AbstractBearerTokenExtractorTest {

    private static final String AUTHORIZATION = "Authorization";
    private static final String COOKIE = "Cookie";

    @Mock
    RuntimeDelegate jaxRsRuntimeDelegate;

    @Mock
    HeaderDelegate<Cookie> jaxRsCookieHeaderDelegate;

    @Mock
    ContainerRequestContext requestContext;

    @Mock
    JWTAuthContextInfo authContextInfo;

    @InjectMocks
    AbstractBearerTokenExtractor target;

    @Before
    public void setUp() {
        target = Mockito.spy(new AbstractBearerTokenExtractor() {});
        MockitoAnnotations.initMocks(this);

        when(jaxRsRuntimeDelegate.createHeaderDelegate(Cookie.class))
                                 .thenReturn(jaxRsCookieHeaderDelegate);

        RuntimeDelegate.setInstance(jaxRsRuntimeDelegate);
    }

    private String getCookieValue(String cookieName) {
        Cookie tokenCookie = requestContext.getCookies().get(cookieName);

        if (tokenCookie != null) {
            return tokenCookie.getValue();
        }
        return null;
    }

    @Test
    public void testGetBearerTokenAuthorizationHeader() {
        when(authContextInfo.getTokenHeader()).thenReturn(AUTHORIZATION);
        when(requestContext.getHeaderString(AUTHORIZATION)).thenReturn("Bearer THE_TOKEN");
        String bearerToken = target.getBearerToken(requestContext::getHeaderString, cookieName -> null);
        assertEquals("THE_TOKEN", bearerToken);
    }

    @Test
    public void testGetBearerTokenMissingAuthorizationHeader() {
        when(authContextInfo.getTokenHeader()).thenReturn(AUTHORIZATION);
        when(requestContext.getHeaderString(AUTHORIZATION)).thenReturn(null);
        String bearerToken = target.getBearerToken(requestContext::getHeaderString, cookieName -> null);
        assertNull(bearerToken);
    }

    @Test
    public void testGetBearerTokenOtherSchemeAuthorizationHeader() {
        when(authContextInfo.getTokenHeader()).thenReturn(AUTHORIZATION);
        when(requestContext.getHeaderString(AUTHORIZATION)).thenReturn("Basic Not_a_JWT");
        String bearerToken = target.getBearerToken(requestContext::getHeaderString, cookieName -> null);
        assertNull(bearerToken);
    }

    @Test
    public void testGetBearerTokenDefaultCookieHeader() {
        final Cookie bearerCookie = new Cookie("Bearer", "THE_TOKEN");
        final Map<String, Cookie> cookieMap = new HashMap<>(1);
        cookieMap.put("Bearer", bearerCookie);

        when(authContextInfo.getTokenHeader()).thenReturn(COOKIE);
        when(requestContext.getCookies()).thenReturn(cookieMap);
        String bearerToken = target.getBearerToken(requestContext::getHeaderString, this::getCookieValue);
        assertEquals("THE_TOKEN", bearerToken);
    }

    @Test
    public void testGetBearerTokenCustomCookieHeader() {
        final Cookie bearerCookie = new Cookie("CustomCookie", "THE_TOKEN");
        final Map<String, Cookie> cookieMap = new HashMap<>(1);
        cookieMap.put("CustomCookie", bearerCookie);

        when(authContextInfo.getTokenHeader()).thenReturn(COOKIE);
        when(authContextInfo.getTokenCookie()).thenReturn("CustomCookie");
        when(requestContext.getCookies()).thenReturn(cookieMap);
        String bearerToken = target.getBearerToken(requestContext::getHeaderString, this::getCookieValue);
        assertEquals("THE_TOKEN", bearerToken);
    }

    @Test
    public void testGetBearerTokenMissingCookieHeader() {
        when(authContextInfo.getTokenHeader()).thenReturn(COOKIE);
        when(requestContext.getCookies()).thenReturn(Collections.emptyMap());
        String bearerToken = target.getBearerToken(requestContext::getHeaderString, this::getCookieValue);
        assertNull(bearerToken);
    }
}
