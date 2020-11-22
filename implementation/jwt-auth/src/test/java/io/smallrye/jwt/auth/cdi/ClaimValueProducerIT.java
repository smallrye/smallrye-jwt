package io.smallrye.jwt.auth.cdi;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.NoSuchElementException;
import java.util.Optional;

import javax.enterprise.util.TypeLiteral;

import org.eclipse.microprofile.jwt.ClaimValue;
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

public class ClaimValueProducerIT {

    @Rule
    public WeldInitiator weld = WeldInitiator.of(PrincipalProducer.class,
            CommonJwtProducer.class,
            ClaimValueProducer.class,
            ClaimValue.class);

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

    @SuppressWarnings("unchecked")
    <T> ClaimValue<T> selectClaimValue(String name) {
        return weld.select(ClaimValue.class, new ClaimQualifier(name, null)).get();
    }

    @SuppressWarnings({ "serial" })
    <T> ClaimValue<Optional<T>> selectOptionalClaimValue(String name) {
        return weld.select(new TypeLiteral<ClaimValue<Optional<T>>>() {
        },
                new ClaimQualifier(name, null)).get();
    }

    @Test
    public void testIssuerNull() {
        ClaimValue<String> issuer = selectClaimValue("iss");
        assertNotNull(issuer);
        assertEquals("iss", issuer.getName());
        assertNull(issuer.getValue());
    }

    @Test
    public void testIssuerInjected() {
        jwtProducer = weld.select(PrincipalProducer.class).get();
        jwtProducer.setJsonWebToken(jwt);
        Mockito.when(jwt.claim(Claims.iss.name())).thenReturn(Optional.of("issuer1"));
        ClaimValue<String> issuer = selectClaimValue("iss");

        assertNotNull(issuer);
        assertEquals("iss", issuer.getName());
        assertEquals("issuer1", issuer.getValue());
    }

    @Test(expected = NoSuchElementException.class)
    public void testOptionalIssuerNotPresent() {
        ClaimValue<Optional<String>> issuer = selectOptionalClaimValue("iss");

        assertNotNull(issuer);
        assertEquals("iss", issuer.getName());
        assertTrue(!issuer.getValue().isPresent());
        issuer.getValue().get();
    }

    @Test
    public void testOptionalIssuerInjected() {
        jwtProducer = weld.select(PrincipalProducer.class).get();
        jwtProducer.setJsonWebToken(jwt);
        Mockito.when(jwt.claim(Claims.iss.name())).thenReturn(Optional.of("issuer1"));
        ClaimValue<Optional<String>> issuer = selectOptionalClaimValue("iss");

        assertNotNull(issuer);
        assertEquals("iss", issuer.getName());
        assertTrue(issuer.getValue().isPresent());
        assertEquals("issuer1", issuer.getValue().get());
    }
}
