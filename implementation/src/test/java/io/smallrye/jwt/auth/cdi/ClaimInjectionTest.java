package io.smallrye.jwt.auth.cdi;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import javax.json.JsonNumber;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.ClaimValue;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.weld.junit4.WeldInitiator;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.junit.Rule;
import org.junit.Test;

import io.smallrye.jwt.KeyUtils;
import io.smallrye.jwt.auth.principal.DefaultJWTCallerPrincipal;
import io.smallrye.jwt.build.Jwt;

@SuppressWarnings("CdiUnproxyableBeanTypesInspection")
public class ClaimInjectionTest {
    @Rule
    public WeldInitiator weld = WeldInitiator.from(
            ClaimInjectionTest.class,
            ClaimsBean.class,
            RawClaimTypeProducer.class,
            ClaimValueProducer.class,
            CommonJwtProducer.class)
            .addBeans()
            .activate(RequestScoped.class)
            .inject(this)
            .build();

    @Inject
    private JsonWebToken jsonWebToken;
    @Inject
    private ClaimsBean claimsBean;

    @Test
    public void inject() {
        assertTrue(claimsBean.isBooleanClaim());
        assertTrue(claimsBean.getBooleanClaimWrapper());
        //assertTrue(claimsBean.getBooleanClaimValue().getValue()); // does not unwrap json to wrapper type
        assertEquals(999, claimsBean.getLongClaim());
        assertEquals(999, claimsBean.getLongClaimWrapper().longValue());
        //assertEquals(999, claimsBean.getLongClaimValue().getValue().longValue()); // does not unwrap json to wrapper type
        assertEquals(999, claimsBean.getLongClaimValueJson().getValue().longValue());
    }

    @Produces
    @RequestScoped
    private static JsonWebToken jwt() throws Exception {
        String jwt = Jwt.claims("/token-claims.json").sign();
        JsonWebSignature jws = new JsonWebSignature();
        jws.setKey(KeyUtils.readPublicKey("/publicKey.pem"));
        jws.setCompactSerialization(jwt);
        JwtClaims claims = JwtClaims.parse(jws.getPayload());
        return new DefaultJWTCallerPrincipal(jwt, claims);
    }

    @RequestScoped
    private static class ClaimsBean {
        @Inject
        @Claim("boolean")
        private boolean booleanClaim;
        @Inject
        @Claim("boolean")
        private Boolean booleanClaimWrapper;
        //@Inject
        //(@Claim("boolean")
        private ClaimValue<Boolean> booleanClaimValue;
        @Inject
        @Claim("long")
        private long longClaim;
        @Inject
        @Claim("long")
        private Long longClaimWrapper;
        //@Inject
        //@Claim("long")
        private ClaimValue<Long> longClaimValue;
        @Inject
        @Claim("long")
        private ClaimValue<JsonNumber> longClaimValueJson;

        boolean isBooleanClaim() {
            return booleanClaim;
        }

        Boolean getBooleanClaimWrapper() {
            return booleanClaimWrapper;
        }

        ClaimValue<Boolean> getBooleanClaimValue() {
            return booleanClaimValue;
        }

        long getLongClaim() {
            return longClaim;
        }

        Long getLongClaimWrapper() {
            return longClaimWrapper;
        }

        ClaimValue<Long> getLongClaimValue() {
            return longClaimValue;
        }

        ClaimValue<JsonNumber> getLongClaimValueJson() {
            return longClaimValueJson;
        }
    }
}
