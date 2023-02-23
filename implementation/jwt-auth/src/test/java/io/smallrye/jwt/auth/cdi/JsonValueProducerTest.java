package io.smallrye.jwt.auth.cdi;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.HashMap;
import java.util.Optional;

import jakarta.json.JsonString;
import jakarta.json.JsonValue;

import org.eclipse.microprofile.jwt.Claims;
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
class JsonValueProducerTest {
    @WeldSetup
    WeldInitiator weld = WeldInitiator.of(PrincipalProducer.class,
            CommonJwtProducer.class,
            JsonValueProducer.class);

    @Mock
    JsonWebToken jwt;

    BoundRequestContext context;
    PrincipalProducer jwtProducer;

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

    <T extends JsonValue> T selectJsonValue(String name, Class<T> type) {
        return weld.select(type, new ClaimQualifier(name, null)).get();
    }

    @Test
    void issuerNullPointerException() {
        JsonString issuer = selectJsonValue("iss", JsonString.class);
        assertNull(issuer);
    }

    @Test
    void issuerInjected() {
        jwtProducer = weld.select(PrincipalProducer.class).get();
        jwtProducer.setJsonWebToken(jwt);
        Mockito.when(jwt.claim(Claims.iss.name())).thenReturn(Optional.of("issuer1"));
        JsonString issuer = selectJsonValue("iss", JsonString.class);

        assertNotNull(issuer);
        assertEquals("issuer1", issuer.getString());
    }
}
