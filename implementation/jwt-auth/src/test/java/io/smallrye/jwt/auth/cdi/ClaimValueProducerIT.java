package io.smallrye.jwt.auth.cdi;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.NoSuchElementException;
import java.util.Optional;

import jakarta.enterprise.util.TypeLiteral;

import org.eclipse.microprofile.jwt.ClaimValue;
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
class ClaimValueProducerIT {
    @WeldSetup
    WeldInitiator weld = WeldInitiator.of(PrincipalProducer.class,
            CommonJwtProducer.class,
            ClaimValueProducer.class,
            ClaimValue.class);

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
    void issuerNull() {
        ClaimValue<String> issuer = selectClaimValue("iss");
        assertNotNull(issuer);
        assertEquals("iss", issuer.getName());
        assertNull(issuer.getValue());
    }

    @Test
    void issuerInjected() {
        jwtProducer = weld.select(PrincipalProducer.class).get();
        jwtProducer.setJsonWebToken(jwt);
        Mockito.when(jwt.claim(Claims.iss.name())).thenReturn(Optional.of("issuer1"));
        ClaimValue<String> issuer = selectClaimValue("iss");

        assertNotNull(issuer);
        assertEquals("iss", issuer.getName());
        assertEquals("issuer1", issuer.getValue());
    }

    @Test
    void optionalIssuerNotPresent() {
        ClaimValue<Optional<String>> issuer = selectOptionalClaimValue("iss");

        assertNotNull(issuer);
        assertEquals("iss", issuer.getName());
        assertFalse(issuer.getValue().isPresent());
        assertThrows(NoSuchElementException.class, () -> issuer.getValue().get());
    }

    @Test
    void optionalIssuerInjected() {
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
