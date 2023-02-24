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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;

class AbstractBearerTokenExtractorTest {

    private static final String AUTHORIZATION = "Authorization";
    private static final String COOKIE = "Cookie";
    private static final List<String> BEARER_SCHEME = Collections.singletonList("Bearer");

    @Mock
    JWTAuthContextInfo authContextInfo;

    @BeforeEach
    void setUp() {
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
    void getBearerTokenAuthorizationHeader() {
        when(authContextInfo.getTokenHeader()).thenReturn(AUTHORIZATION);
        when(authContextInfo.getTokenSchemes()).thenReturn(BEARER_SCHEME);
        AbstractBearerTokenExtractor target = newTarget(h -> "Bearer THE_TOKEN", c -> null);
        String bearerToken = target.getBearerToken();
        assertEquals("THE_TOKEN", bearerToken);
    }

    @Test
    void getBearerTokenAuthorizationHeaderMixedCase() {
        when(authContextInfo.getTokenHeader()).thenReturn(AUTHORIZATION);
        when(authContextInfo.getTokenSchemes()).thenReturn(BEARER_SCHEME);
        AbstractBearerTokenExtractor target = newTarget(h -> "bEaReR THE_TOKEN", c -> null);
        String bearerToken = target.getBearerToken();
        assertEquals("THE_TOKEN", bearerToken);
    }

    @Test
    void getBearerTokenAuthorizationHeaderBlank() {
        when(authContextInfo.getTokenHeader()).thenReturn(AUTHORIZATION);
        when(authContextInfo.getTokenSchemes()).thenReturn(BEARER_SCHEME);
        AbstractBearerTokenExtractor target = newTarget(h -> "BEARER ", c -> null);
        String bearerToken = target.getBearerToken();
        assertEquals("", bearerToken);
    }

    @Test
    void getBearerTokenAuthorizationHeaderInvalidSchemePrefix() {
        when(authContextInfo.getTokenHeader()).thenReturn(AUTHORIZATION);
        when(authContextInfo.getTokenSchemes()).thenReturn(BEARER_SCHEME);
        AbstractBearerTokenExtractor target = newTarget(h -> "BEARER", c -> null);
        String bearerToken = target.getBearerToken();
        assertNull(bearerToken);
    }

    @Test
    void getBearerTokenMissingAuthorizationHeader() {
        when(authContextInfo.getTokenHeader()).thenReturn(AUTHORIZATION);
        when(authContextInfo.getTokenSchemes()).thenReturn(BEARER_SCHEME);
        AbstractBearerTokenExtractor target = newTarget(h -> null, c -> null);
        String bearerToken = target.getBearerToken();
        assertNull(bearerToken);
    }

    @Test
    void getBearerTokenOtherSchemeAuthorizationHeader() {
        when(authContextInfo.getTokenHeader()).thenReturn(AUTHORIZATION);
        when(authContextInfo.getTokenSchemes()).thenReturn(BEARER_SCHEME);
        AbstractBearerTokenExtractor target = newTarget(h -> "Basic Not_a_JWT", c -> null);
        String bearerToken = target.getBearerToken();
        assertNull(bearerToken);
    }

    @Test
    void getBearerTokenCustomSchemeAuthorizationHeader() {
        when(authContextInfo.getTokenHeader()).thenReturn(AUTHORIZATION);
        when(authContextInfo.getTokenSchemes()).thenReturn(Arrays.asList("Bearer", "DPoP"));
        AbstractBearerTokenExtractor target = newTarget(h -> "DPoP THE_TOKEN", c -> null);
        String bearerToken = target.getBearerToken();
        assertEquals("THE_TOKEN", bearerToken);
    }

    @Test
    void getBearerTokenCustomHeader() {
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
    void getBearerTokenCustomHeaderAndScheme() {
        when(authContextInfo.getTokenHeader()).thenReturn("MyHeader");
        when(authContextInfo.getTokenSchemes()).thenReturn(Arrays.asList("DPoP"));
        AbstractBearerTokenExtractor target = newTarget(h -> {
            if ("MyHeader".equals(h)) {
                return "DPoP THE_CUSTOM_TOKEN";
            }
            return null;
        }, c -> null);
        String bearerToken = target.getBearerToken();
        assertEquals("THE_CUSTOM_TOKEN", bearerToken);
    }

    @Test
    void getBearerTokenDefaultCookieHeader() {
        when(authContextInfo.getTokenHeader()).thenReturn(COOKIE);
        AbstractBearerTokenExtractor target = newTarget(h -> null, c -> "THE_TOKEN");
        String bearerToken = target.getBearerToken();
        assertEquals("THE_TOKEN", bearerToken);
    }

    @Test
    void getBearerTokenCustomCookieHeader() {
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
    void getBearerTokenMissingCookieHeader() {
        when(authContextInfo.getTokenHeader()).thenReturn(COOKIE);
        AbstractBearerTokenExtractor target = newTarget(h -> null, c -> null);
        String bearerToken = target.getBearerToken();
        assertNull(bearerToken);
    }

    @Test
    void getBearerTokenFallbackToHeaderWithCookieHeader() {
        when(authContextInfo.getTokenHeader()).thenReturn(COOKIE);
        when(authContextInfo.isAlwaysCheckAuthorization()).thenReturn(true);
        AbstractBearerTokenExtractor target = newTarget(h -> "Bearer THE_HEADER_TOKEN", c -> "THE_COOKIE_TOKEN");
        String bearerToken = target.getBearerToken();
        assertEquals("THE_COOKIE_TOKEN", bearerToken);
    }

    @Test
    void getBearerTokenFallbackToHeaderWithEmptyCookie() {
        when(authContextInfo.getTokenHeader()).thenReturn(COOKIE);
        when(authContextInfo.getTokenSchemes()).thenReturn(BEARER_SCHEME);
        when(authContextInfo.isAlwaysCheckAuthorization()).thenReturn(true);

        AbstractBearerTokenExtractor target = newTarget(h -> "Bearer THE_TOKEN", c -> null);
        String bearerToken = target.getBearerToken();
        assertEquals("THE_TOKEN", bearerToken);
    }
}
