package io.smallrye.jwt.auth.cdi;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.Collections;
import java.util.HashMap;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.weld.context.bound.BoundRequestContext;
import org.jboss.weld.junit4.WeldInitiator;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

public class PrincipalProducerIT {

    @Rule
    public WeldInitiator weld = WeldInitiator.of(PrincipalProducer.class);

    @Mock
    JsonWebToken jwt;

    BoundRequestContext context;
    PrincipalProducer jwtProducer;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        context = weld.select(BoundRequestContext.class).get();
        context.associate(new HashMap<String, Object>());
        // Start Request Scope
        context.activate();
    }

    @After
    public void tearDown() {
        // End Request Scope
        context.deactivate();
    }

    @Test
    public void testNullPrincipal() {
        JsonWebToken jwt = weld.select(JsonWebToken.class).get();
        assertNotNull(jwt);
        assertNull(jwt.getName());
        assertNull(jwt.getClaimNames());
    }

    @Test
    public void testPrincipalInjected() {
        PrincipalProducer jwtProducer = weld.select(PrincipalProducer.class).get();
        Mockito.when(jwt.getName()).thenReturn("User1");
        Mockito.when(jwt.getClaimNames()).thenReturn(Collections.singleton("upn"));
        jwtProducer.setJsonWebToken(jwt);

        JsonWebToken jwt = weld.select(JsonWebToken.class).get();
        assertNotNull(jwt);
        assertEquals("User1", jwt.getName());
    }
}
