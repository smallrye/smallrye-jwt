package io.smallrye.jwt.auth.cdi;

import static org.hamcrest.core.IsCollectionContaining.hasItems;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Optional;
import java.util.Set;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Instance;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import javax.json.JsonArray;
import javax.json.JsonNumber;
import javax.json.JsonObject;
import javax.json.JsonString;
import javax.json.JsonValue;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.ClaimValue;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.hamcrest.MatcherAssert;
import org.jboss.weld.junit4.WeldInitiator;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.junit.Rule;
import org.junit.Test;

import io.smallrye.jwt.KeyUtils;
import io.smallrye.jwt.auth.principal.DefaultJWTCallerPrincipal;
import io.smallrye.jwt.build.Jwt;

@SuppressWarnings({
        "CdiUnproxyableBeanTypesInspection",
        "OptionalGetWithoutIsPresent"
})
public class ClaimInjectionTest {
    @Rule
    public WeldInitiator weld = WeldInitiator.from(
            ClaimInjectionTest.class,
            ClaimsBean.class,
            ClaimBeanInstance.class,
            RawClaimTypeProducer.class,
            OptionalClaimTypeProducer.class,
            ClaimValueProducer.class,
            JsonValueProducer.class,
            CommonJwtProducer.class)
            .addBeans()
            .activate(RequestScoped.class, ApplicationScoped.class)
            .inject(this)
            .build();

    @Inject
    private ClaimsBean claimsBean;
    @Inject
    private ClaimBeanInstance claimBeanInstance;

    @Test
    public void injectBoolean() {
        assertTrue(claimsBean.isBooleanClaim());
        assertTrue(claimsBean.getBooleanClaimWrapper());
        assertTrue(claimsBean.getBooleanClaimValue().getValue());
        assertTrue(claimsBean.getBooleanOptional().get());
        assertTrue(claimsBean.getBooleanClaimValueOptional().getValue().get());
        // This doesn't work because it causes ambiguous dependencies for JsonValue in JsonValueProducer
        //assertEquals(claimsBean.getBooleanJson(), JsonValue.TRUE);
        //assertEquals(claimsBean.getBooleanOptionalJson().get(), JsonValue.TRUE);
        //assertEquals(claimsBean.getBooleanClaimValueJson().getValue(), JsonValue.TRUE);
        //assertEquals(claimsBean.getBooleanClaimValueOptional().getValue().get(), JsonValue.TRUE);

        assertTrue(claimBeanInstance.getBooleanClaimWrapper().get());
        assertTrue(claimBeanInstance.getBooleanOptional().get().get());
    }

    @Test
    public void injectLong() {
        assertEquals(999, claimsBean.getLongClaim());
        assertEquals(999, claimsBean.getLongClaimWrapper().longValue());
        assertEquals(999, claimsBean.getLongClaimValue().getValue().longValue());
        assertEquals(999, claimsBean.getLongOptional().get().longValue());
        assertEquals(999, claimsBean.getLongClaimValueOptional().getValue().get().longValue());
        assertEquals(999, claimsBean.getLongJson().longValue());
        assertEquals(999, claimsBean.getLongOptionalJson().get().longValue());
        assertEquals(999, claimsBean.getLongClaimValueJson().getValue().longValue());
        assertEquals(999, claimsBean.getLongClaimValueOptionalJson().getValue().get().longValue());

        assertEquals(999, claimBeanInstance.getLongClaimWrapper().get().longValue());
        assertEquals(999, claimBeanInstance.getLongOptional().get().get().longValue());
        assertEquals(999, claimBeanInstance.getLongJson().get().longValue());
        assertEquals(999, claimBeanInstance.getLongOptionalJson().get().get().longValue());
    }

    @Test
    public void injectString() {
        assertEquals("string", claimsBean.getStringClaim());
        assertEquals("string", claimsBean.getStringClaimValue().getValue());
        assertEquals("string", claimsBean.getStringOptional().get());
        assertEquals("string", claimsBean.getStringClaimValueOptional().getValue().get());
        assertEquals("string", claimsBean.getStringJson().getString());
        assertEquals("string", claimsBean.getStringOptionalJson().get().getString());
        assertEquals("string", claimsBean.getStringClaimValueJson().getValue().getString());
        assertEquals("string", claimsBean.getStringClaimValueOptionalJson().getValue().get().getString());

        assertEquals("string", claimBeanInstance.getStringClaim().get());
        assertEquals("string", claimBeanInstance.getStringOptional().get().get());
        assertEquals("string", claimBeanInstance.getStringJson().get().getString());
        assertEquals("string", claimBeanInstance.getStringOptionalJson().get().get().getString());
    }

    @Test
    public void injectSet() {
        MatcherAssert.assertThat(claimsBean.getSetClaim(), hasItems("value0", "value1", "value2"));
        MatcherAssert.assertThat(claimsBean.getSetClaimValue().getValue(), hasItems("value0", "value1", "value2"));
        MatcherAssert.assertThat(claimsBean.getSetOptional().get(), hasItems("value0", "value1", "value2"));
        MatcherAssert.assertThat(claimsBean.getSetClaimValueOptional().getValue().get(),
                hasItems("value0", "value1", "value2"));

        MatcherAssert.assertThat(claimsBean.getSetJson().getValuesAs(JsonString::getString),
                hasItems("value0", "value1", "value2"));
        MatcherAssert.assertThat(claimsBean.getSetOptionalJson().get().getValuesAs(JsonString::getString),
                hasItems("value0", "value1", "value2"));
        MatcherAssert.assertThat(claimsBean.getSetClaimValueJson().getValue().getValuesAs(JsonString::getString),
                hasItems("value0", "value1", "value2"));
        MatcherAssert.assertThat(claimsBean.getSetClaimValueOptionalJson().getValue().get().getValuesAs(JsonString::getString),
                hasItems("value0", "value1", "value2"));

        MatcherAssert.assertThat(claimBeanInstance.getSetClaim().get(),
                hasItems("value0", "value1", "value2"));
        MatcherAssert.assertThat(claimBeanInstance.getSetOptional().get().get(),
                hasItems("value0", "value1", "value2"));
        MatcherAssert.assertThat(claimBeanInstance.getSetJson().get().getValuesAs(JsonString::getString),
                hasItems("value0", "value1", "value2"));
        MatcherAssert.assertThat(claimBeanInstance.getSetOptionalJson().get().get().getValuesAs(JsonString::getString),
                hasItems("value0", "value1", "value2"));
    }

    @Test
    public void injectObject() {
        //assertEquals("street", claimsBean.getAddressClaim().getCode()); // No inject of Claim type directly supported, since we don't have a producer for it.
        //assertEquals("street", claimsBean.getAddressClaimValue().getValue().getCode()); // We just let retrieve the type, but no conversion for custom type, so ClassCastException
        //assertEquals("street", claimsBean.getAddressOptional().get().getCode()); // No inject of Optional type directly supported, since we don't have a producer for it.
        //assertEquals("street", claimsBean.getAddressClaimValueOptional().getValue().get().getCode()); // We just let retrieve the type, but no conversion for custom type, so ClassCastException

        assertEquals("street", claimsBean.getAddressJson().getString("street"));
        assertEquals("street", claimsBean.getAddressOptionalJson().get().getString("street"));
        assertEquals("street", claimsBean.getAddressClaimValueJson().getValue().getString("street"));
        assertEquals("street", claimsBean.getAddressClaimValueOptionalJson().getValue().get().getString("street"));
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

    @SuppressWarnings({
            "unused",
            "OptionalUsedAsFieldOrParameterType"
    })
    @RequestScoped
    private static class ClaimsBean {
        @Inject
        @Claim("boolean")
        private boolean booleanClaim;
        @Inject
        @Claim("boolean")
        private Boolean booleanClaimWrapper;
        @Inject
        @Claim("boolean")
        private ClaimValue<Boolean> booleanClaimValue;
        @Inject
        @Claim("boolean")
        private Optional<Boolean> booleanOptional;
        @Inject
        @Claim("boolean")
        private ClaimValue<Optional<Boolean>> booleanClaimValueOptional;
        //@Inject
        //@Claim("boolean")
        private JsonValue booleanJson;
        //@Inject
        //@Claim("boolean")
        private Optional<JsonValue> booleanOptionalJson;
        //@Inject
        //@Claim("boolean")
        private ClaimValue<JsonValue> booleanClaimValueJson;
        //@Inject
        //@Claim("boolean")
        private ClaimValue<Optional<JsonValue>> booleanClaimValueOptionalJson;

        @Inject
        @Claim("long")
        private long longClaim;
        @Inject
        @Claim("long")
        private Long longClaimWrapper;
        @Inject
        @Claim("long")
        private ClaimValue<Long> longClaimValue;
        @Inject
        @Claim("long")
        private Optional<Long> longOptional;
        @Inject
        @Claim("long")
        private ClaimValue<Optional<Long>> longClaimValueOptional;
        @Inject
        @Claim("long")
        private JsonNumber longJson;
        @Inject
        @Claim("long")
        private Optional<JsonNumber> longOptionalJson;
        @Inject
        @Claim("long")
        private ClaimValue<JsonNumber> longClaimValueJson;
        @Inject
        @Claim("long")
        private ClaimValue<Optional<JsonNumber>> longClaimValueOptionalJson;

        @Inject
        @Claim("string")
        private String stringClaim;
        @Inject
        @Claim("string")
        private ClaimValue<String> stringClaimValue;
        @Inject
        @Claim("string")
        private Optional<String> stringOptional;
        @Inject
        @Claim("string")
        private ClaimValue<Optional<String>> stringClaimValueOptional;
        @Inject
        @Claim("string")
        private JsonString stringJson;
        @Inject
        @Claim("string")
        private Optional<JsonString> stringOptionalJson;
        @Inject
        @Claim("string")
        private ClaimValue<JsonString> stringClaimValueJson;
        @Inject
        @Claim("string")
        private ClaimValue<Optional<JsonString>> stringClaimValueOptionalJson;

        @Inject
        @Claim("stringArray")
        private Set<String> setClaim;
        @Inject
        @Claim("stringArray")
        private ClaimValue<Set<String>> setClaimValue;
        @Inject
        @Claim("stringArray")
        private Optional<Set<String>> setOptional;
        @Inject
        @Claim("stringArray")
        private ClaimValue<Optional<Set<String>>> setClaimValueOptional;
        @Inject
        @Claim("stringArray")
        private JsonArray setJson;
        @Inject
        @Claim("stringArray")
        private Optional<JsonArray> setOptionalJson;
        @Inject
        @Claim("stringArray")
        private ClaimValue<JsonArray> setClaimValueJson;
        @Inject
        @Claim("stringArray")
        private ClaimValue<Optional<JsonArray>> setClaimValueOptionalJson;

        //@Inject
        //@Claim("string")
        private Address addressClaim;
        @Inject
        @Claim("address")
        private ClaimValue<Address> addressClaimValue;
        //@Inject
        //@Claim("address")
        private Optional<Address> addressOptional;
        @Inject
        @Claim("address")
        private ClaimValue<Optional<Address>> addressClaimValueOptional;
        @Inject
        @Claim("address")
        private JsonObject addressJson;
        @Inject
        @Claim("address")
        private Optional<JsonObject> addressOptionalJson;
        @Inject
        @Claim("address")
        private ClaimValue<JsonObject> addressClaimValueJson;
        @Inject
        @Claim("address")
        private ClaimValue<Optional<JsonObject>> addressClaimValueOptionalJson;

        boolean isBooleanClaim() {
            return booleanClaim;
        }

        Boolean getBooleanClaimWrapper() {
            return booleanClaimWrapper;
        }

        ClaimValue<Boolean> getBooleanClaimValue() {
            return booleanClaimValue;
        }

        Optional<Boolean> getBooleanOptional() {
            return booleanOptional;
        }

        ClaimValue<Optional<Boolean>> getBooleanClaimValueOptional() {
            return booleanClaimValueOptional;
        }

        JsonValue getBooleanJson() {
            return booleanJson;
        }

        Optional<JsonValue> getBooleanOptionalJson() {
            return booleanOptionalJson;
        }

        ClaimValue<JsonValue> getBooleanClaimValueJson() {
            return booleanClaimValueJson;
        }

        ClaimValue<Optional<JsonValue>> getBooleanClaimValueOptionalJson() {
            return booleanClaimValueOptionalJson;
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

        Optional<Long> getLongOptional() {
            return longOptional;
        }

        ClaimValue<Optional<Long>> getLongClaimValueOptional() {
            return longClaimValueOptional;
        }

        JsonNumber getLongJson() {
            return longJson;
        }

        Optional<JsonNumber> getLongOptionalJson() {
            return longOptionalJson;
        }

        ClaimValue<JsonNumber> getLongClaimValueJson() {
            return longClaimValueJson;
        }

        ClaimValue<Optional<JsonNumber>> getLongClaimValueOptionalJson() {
            return longClaimValueOptionalJson;
        }

        String getStringClaim() {
            return stringClaim;
        }

        ClaimValue<String> getStringClaimValue() {
            return stringClaimValue;
        }

        Optional<String> getStringOptional() {
            return stringOptional;
        }

        ClaimValue<Optional<String>> getStringClaimValueOptional() {
            return stringClaimValueOptional;
        }

        JsonString getStringJson() {
            return stringJson;
        }

        Optional<JsonString> getStringOptionalJson() {
            return stringOptionalJson;
        }

        ClaimValue<JsonString> getStringClaimValueJson() {
            return stringClaimValueJson;
        }

        ClaimValue<Optional<JsonString>> getStringClaimValueOptionalJson() {
            return stringClaimValueOptionalJson;
        }

        Set<String> getSetClaim() {
            return setClaim;
        }

        ClaimValue<Set<String>> getSetClaimValue() {
            return setClaimValue;
        }

        Optional<Set<String>> getSetOptional() {
            return setOptional;
        }

        ClaimValue<Optional<Set<String>>> getSetClaimValueOptional() {
            return setClaimValueOptional;
        }

        JsonArray getSetJson() {
            return setJson;
        }

        Optional<JsonArray> getSetOptionalJson() {
            return setOptionalJson;
        }

        ClaimValue<JsonArray> getSetClaimValueJson() {
            return setClaimValueJson;
        }

        ClaimValue<Optional<JsonArray>> getSetClaimValueOptionalJson() {
            return setClaimValueOptionalJson;
        }

        Address getAddressClaim() {
            return addressClaim;
        }

        ClaimValue<Address> getAddressClaimValue() {
            return addressClaimValue;
        }

        Optional<Address> getAddressOptional() {
            return addressOptional;
        }

        ClaimValue<Optional<Address>> getAddressClaimValueOptional() {
            return addressClaimValueOptional;
        }

        JsonObject getAddressJson() {
            return addressJson;
        }

        Optional<JsonObject> getAddressOptionalJson() {
            return addressOptionalJson;
        }

        ClaimValue<JsonObject> getAddressClaimValueJson() {
            return addressClaimValueJson;
        }

        ClaimValue<Optional<JsonObject>> getAddressClaimValueOptionalJson() {
            return addressClaimValueOptionalJson;
        }
    }

    @ApplicationScoped
    private static class ClaimBeanInstance {
        @Inject
        @Claim("boolean")
        private Instance<Boolean> booleanClaimWrapper;
        @Inject
        @Claim("boolean")
        private Instance<Optional<Boolean>> booleanOptional;
        @Inject
        @Claim("long")
        private Instance<Long> longClaimWrapper;
        @Inject
        @Claim("long")
        private Instance<Optional<Long>> longOptional;
        @Inject
        @Claim("long")
        private Instance<JsonNumber> longJson;
        @Inject
        @Claim("long")
        private Instance<Optional<JsonNumber>> longOptionalJson;
        @Inject
        @Claim("string")
        private Instance<String> stringClaim;
        @Inject
        @Claim("string")
        private Instance<Optional<String>> stringOptional;
        @Inject
        @Claim("string")
        private Instance<JsonString> stringJson;
        @Inject
        @Claim("string")
        private Instance<Optional<JsonString>> stringOptionalJson;
        @Inject
        @Claim("stringArray")
        private Instance<Set<String>> setClaim;
        @Inject
        @Claim("stringArray")
        private Instance<Optional<Set<String>>> setOptional;
        @Inject
        @Claim("stringArray")
        private Instance<JsonArray> setJson;
        @Inject
        @Claim("stringArray")
        private Instance<Optional<JsonArray>> setOptionalJson;

        Instance<Boolean> getBooleanClaimWrapper() {
            return booleanClaimWrapper;
        }

        Instance<Optional<Boolean>> getBooleanOptional() {
            return booleanOptional;
        }

        Instance<Long> getLongClaimWrapper() {
            return longClaimWrapper;
        }

        Instance<Optional<Long>> getLongOptional() {
            return longOptional;
        }

        Instance<JsonNumber> getLongJson() {
            return longJson;
        }

        Instance<Optional<JsonNumber>> getLongOptionalJson() {
            return longOptionalJson;
        }

        Instance<String> getStringClaim() {
            return stringClaim;
        }

        Instance<Optional<String>> getStringOptional() {
            return stringOptional;
        }

        Instance<JsonString> getStringJson() {
            return stringJson;
        }

        Instance<Optional<JsonString>> getStringOptionalJson() {
            return stringOptionalJson;
        }

        Instance<Set<String>> getSetClaim() {
            return setClaim;
        }

        Instance<Optional<Set<String>>> getSetOptional() {
            return setOptional;
        }

        Instance<JsonArray> getSetJson() {
            return setJson;
        }

        Instance<Optional<JsonArray>> getSetOptionalJson() {
            return setOptionalJson;
        }
    }

    public static class Address {
        private String street;
        private String code;

        public String getStreet() {
            return street;
        }

        public void setStreet(final String street) {
            this.street = street;
        }

        public String getCode() {
            return code;
        }

        public void setCode(final String code) {
            this.code = code;
        }
    }
}
