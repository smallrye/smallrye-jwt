package io.smallrye.jwt.auth.cdi;

import static org.junit.Assert.assertTrue;

import java.util.HashMap;

import org.jboss.weld.context.bound.BoundRequestContext;
import org.jboss.weld.junit4.WeldInitiator;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import io.smallrye.jwt.auth.principal.DefaultJWTCallerPrincipalFactory;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipalFactory;

public class JWTCallerPrincipalFactoryProducerTest {

    @Rule
    public WeldInitiator weld = WeldInitiator.of(JWTCallerPrincipalFactoryProducer.class);

    BoundRequestContext context;

    @Before
    public void setUp() {
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
    public void testJWTCallerPrincipalFactory() {
        JWTCallerPrincipalFactory factory = weld.select(JWTCallerPrincipalFactory.class).get();
        assertTrue(factory instanceof DefaultJWTCallerPrincipalFactory);
    }
}
