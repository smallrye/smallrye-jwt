package io.smallrye.jwt.auth.cdi;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.HashMap;
import java.util.Optional;

import javax.json.JsonString;
import javax.json.JsonValue;

import org.eclipse.microprofile.jwt.Claims;
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

public class JsonValueProducerTest {

    @Rule
    public WeldInitiator weld = WeldInitiator.of(PrincipalProducer.class,
            CommonJwtProducer.class,
            JsonValueProducer.class);

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

    <T extends JsonValue> T selectJsonValue(String name, Class<T> type) {
        return weld.select(type, new ClaimQualifier(name, null)).get();
    }

    @Test
    public void testIssuerNullPointerException() {
        JsonString issuer = selectJsonValue("iss", JsonString.class);
        assertNull(issuer);
    }

    @Test
    public void testIssuerInjected() {
        jwtProducer = weld.select(PrincipalProducer.class).get();
        jwtProducer.setJsonWebToken(jwt);
        Mockito.when(jwt.claim(Claims.iss.name())).thenReturn(Optional.of("issuer1"));
        JsonString issuer = selectJsonValue("iss", JsonString.class);

        assertNotNull(issuer);
        assertEquals("issuer1", issuer.getString());
    }
}
