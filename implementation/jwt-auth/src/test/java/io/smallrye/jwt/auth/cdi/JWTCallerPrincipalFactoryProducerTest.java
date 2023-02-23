package io.smallrye.jwt.auth.cdi;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;

import org.jboss.weld.context.bound.BoundRequestContext;
import org.jboss.weld.junit5.WeldInitiator;
import org.jboss.weld.junit5.WeldJunit5Extension;
import org.jboss.weld.junit5.WeldSetup;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import io.smallrye.jwt.auth.principal.DefaultJWTCallerPrincipalFactory;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipalFactory;

@ExtendWith(WeldJunit5Extension.class)
class JWTCallerPrincipalFactoryProducerTest {

    @WeldSetup
    WeldInitiator weld = WeldInitiator.of(JWTCallerPrincipalFactoryProducer.class);

    BoundRequestContext context;

    @BeforeEach
    void setUp() {
        context = weld.select(BoundRequestContext.class).get();
        context.associate(new HashMap<>());
        // Start Request Scope
        context.activate();
    }

    @AfterEach
    void tearDown() {
        // End Request Scope
        context.deactivate();
    }

    @Test
    void jwtCallerPrincipalFactory() {
        JWTCallerPrincipalFactory factory = weld.select(JWTCallerPrincipalFactory.class).get();
        assertTrue(factory instanceof DefaultJWTCallerPrincipalFactory);
    }
}
