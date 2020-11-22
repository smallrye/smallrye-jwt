package io.smallrye.jwt.auth.cdi;

import static org.junit.Assert.assertTrue;

import java.util.HashMap;

import javax.annotation.Priority;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Alternative;

import org.jboss.weld.context.bound.BoundRequestContext;
import org.jboss.weld.junit4.WeldInitiator;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipal;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipalFactory;
import io.smallrye.jwt.auth.principal.ParseException;

public class CustomJWTCallerPrincipalFactoryTest {

    @Rule
    public WeldInitiator weld = WeldInitiator.of(JWTCallerPrincipalFactoryProducer.class, TestFactory.class);

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
        assertTrue(factory instanceof TestFactory);
    }

    @ApplicationScoped
    @Alternative
    @Priority(1)
    public static class TestFactory extends JWTCallerPrincipalFactory {

        @Override
        public JWTCallerPrincipal parse(String token, JWTAuthContextInfo authContextInfo) throws ParseException {
            return null;
        }

    }
}
