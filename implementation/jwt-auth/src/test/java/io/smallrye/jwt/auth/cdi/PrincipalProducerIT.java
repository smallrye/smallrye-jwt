package io.smallrye.jwt.auth.cdi;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Collections;
import java.util.HashMap;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.weld.context.bound.BoundRequestContext;
import org.jboss.weld.junit5.WeldInitiator;
import org.jboss.weld.junit5.WeldJunit5Extension;
import org.jboss.weld.junit5.WeldSetup;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

@ExtendWith(WeldJunit5Extension.class)
class PrincipalProducerIT {

    @WeldSetup
    WeldInitiator weld = WeldInitiator.of(PrincipalProducer.class);

    @Mock
    JsonWebToken jwt;

    BoundRequestContext context;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.initMocks(this);
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
    void nullPrincipal() {
        JsonWebToken jwt = weld.select(JsonWebToken.class).get();
        assertNotNull(jwt);
        assertNull(jwt.getName());
        assertNull(jwt.getClaimNames());
    }

    @Test
    void principalInjected() {
        PrincipalProducer jwtProducer = weld.select(PrincipalProducer.class).get();
        Mockito.when(jwt.getName()).thenReturn("User1");
        Mockito.when(jwt.getClaimNames()).thenReturn(Collections.singleton("upn"));
        jwtProducer.setJsonWebToken(jwt);

        JsonWebToken jwt = weld.select(JsonWebToken.class).get();
        assertNotNull(jwt);
        assertEquals("User1", jwt.getName());
    }
}
