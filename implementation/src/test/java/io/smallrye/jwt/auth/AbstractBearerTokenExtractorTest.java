/*
 *   Copyright 2019 Red Hat, Inc, and individual contributors.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */
package io.smallrye.jwt.auth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;

public class AbstractBearerTokenExtractorTest {

    private static final String AUTHORIZATION = "Authorization";
    private static final String COOKIE = "Cookie";
    private static final List<String> BEARER_SCHEME = Collections.singletonList("Bearer");

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
        when(authContextInfo.getTokenSchemes()).thenReturn(BEARER_SCHEME);
        AbstractBearerTokenExtractor target = newTarget(h -> "Bearer THE_TOKEN", c -> null);
        String bearerToken = target.getBearerToken();
        assertEquals("THE_TOKEN", bearerToken);
    }

    @Test
    public void testGetBearerTokenAuthorizationHeaderMixedCase() {
        when(authContextInfo.getTokenHeader()).thenReturn(AUTHORIZATION);
        when(authContextInfo.getTokenSchemes()).thenReturn(BEARER_SCHEME);
        AbstractBearerTokenExtractor target = newTarget(h -> "bEaReR THE_TOKEN", c -> null);
        String bearerToken = target.getBearerToken();
        assertEquals("THE_TOKEN", bearerToken);
    }

    @Test
    public void testGetBearerTokenAuthorizationHeaderBlank() {
        when(authContextInfo.getTokenHeader()).thenReturn(AUTHORIZATION);
        when(authContextInfo.getTokenSchemes()).thenReturn(BEARER_SCHEME);
        AbstractBearerTokenExtractor target = newTarget(h -> "BEARER ", c -> null);
        String bearerToken = target.getBearerToken();
        assertEquals("", bearerToken);
    }

    @Test
    public void testGetBearerTokenAuthorizationHeaderInvalidSchemePrefix() {
        when(authContextInfo.getTokenHeader()).thenReturn(AUTHORIZATION);
        when(authContextInfo.getTokenSchemes()).thenReturn(BEARER_SCHEME);
        AbstractBearerTokenExtractor target = newTarget(h -> "BEARER", c -> null);
        String bearerToken = target.getBearerToken();
        assertNull(bearerToken);
    }

    @Test
    public void testGetBearerTokenMissingAuthorizationHeader() {
        when(authContextInfo.getTokenHeader()).thenReturn(AUTHORIZATION);
        when(authContextInfo.getTokenSchemes()).thenReturn(BEARER_SCHEME);
        AbstractBearerTokenExtractor target = newTarget(h -> null, c -> null);
        String bearerToken = target.getBearerToken();
        assertNull(bearerToken);
    }

    @Test
    public void testGetBearerTokenOtherSchemeAuthorizationHeader() {
        when(authContextInfo.getTokenHeader()).thenReturn(AUTHORIZATION);
        when(authContextInfo.getTokenSchemes()).thenReturn(BEARER_SCHEME);
        AbstractBearerTokenExtractor target = newTarget(h -> "Basic Not_a_JWT", c -> null);
        String bearerToken = target.getBearerToken();
        assertNull(bearerToken);
    }

    @Test
    public void testGetBearerTokenCustomSchemeAuthorizationHeader() {
        when(authContextInfo.getTokenHeader()).thenReturn(AUTHORIZATION);
        when(authContextInfo.getTokenSchemes()).thenReturn(Arrays.asList("Bearer", "DPoP"));
        AbstractBearerTokenExtractor target = newTarget(h -> "DPoP THE_TOKEN", c -> null);
        String bearerToken = target.getBearerToken();
        assertEquals("THE_TOKEN", bearerToken);
    }

    @Test
    public void testGetBearerTokenCustomHeader() {
        when(authContextInfo.getTokenHeader()).thenReturn("MyHeader");
        AbstractBearerTokenExtractor target = newTarget(h -> {
            if ("MyHeader".equals(h)) {
                return "THE_CUSTOM_TOKEN";
            }
            return null;
        }, c -> null);
        String bearerToken = target.getBearerToken();
        assertEquals("THE_CUSTOM_TOKEN", bearerToken);
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
