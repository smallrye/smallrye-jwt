package io.smallrye.jwt.auth.cdi;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.lang.annotation.Annotation;
import java.lang.reflect.Member;
import java.lang.reflect.Type;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.enterprise.context.Dependent;
import javax.enterprise.context.RequestScoped;
import javax.enterprise.context.spi.CreationalContext;
import javax.enterprise.inject.Default;
import javax.enterprise.inject.Produces;
import javax.enterprise.inject.spi.Annotated;
import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.CDI;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.enterprise.inject.spi.PassivationCapable;
import javax.enterprise.util.AnnotationLiteral;
import javax.inject.Inject;
import javax.json.bind.JsonbBuilder;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.ClaimValue;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.weld.junit4.WeldInitiator;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.junit.Rule;
import org.junit.Test;

import io.smallrye.converters.SmallRyeConvertersBuilder;
import io.smallrye.converters.api.Converter;
import io.smallrye.converters.api.Converters;
import io.smallrye.jwt.KeyUtils;
import io.smallrye.jwt.auth.principal.DefaultJWTCallerPrincipal;
import io.smallrye.jwt.build.Jwt;

@SuppressWarnings("CdiUnproxyableBeanTypesInspection")
public class ClaimConverterTest {
    @Rule
    public WeldInitiator weld = WeldInitiator.from(
            ClaimInjectionBean.class,
            ClaimConverterTest.class,
            RawConverterBean.class,
            ClaimConverterBean.class,
            ClaimValueProducer.class,
            CommonJwtProducer.class)
            .addBeans()
            .activate(RequestScoped.class)
            // This will auto register with an Extension and the Type of the injection Point.
            .addBeans(new ClaimInjectionBean<>(String.class))
            .addBeans(new ClaimInjectionBean<>(Byte.class))
            .addBeans(new ClaimInjectionBean<>(Short.class))
            .addBeans(new ClaimInjectionBean<>(Integer.class))
            .addBeans(new ClaimInjectionBean<>(Long.class))
            .addBeans(new ClaimInjectionBean<>(Float.class))
            .addBeans(new ClaimInjectionBean<>(Double.class))
            .addBeans(new ClaimInjectionBean<>(Boolean.class))
            .addBeans(new ClaimInjectionBean<>(Character.class))
            .addBeans(new ClaimInjectionBean<>(Address.class))
            .inject(this)
            .build();

    @Inject
    private JsonWebToken jsonWebToken;
    @Inject
    private RawConverterBean raw;
    @Inject
    private ClaimConverterBean claim;

    @Test
    public void convertString() {
        assertEquals("jdoe", raw.getName());
        assertEquals("jdoe", claim.getName().getValue());
        assertEquals("jdoe", jsonWebToken.<String> getClaim("preferred_username"));
    }

    @Test
    public void convertRawWrapperTypes() {
        assertEquals(1, raw.getByteClaim().byteValue());
        assertEquals(9, raw.getShortClaim().shortValue());
        assertEquals(99, raw.getIntegerClaim().intValue());
        assertEquals(999, raw.getLongClaim().longValue());
        assertEquals(99.9, raw.getFloatClaim(), 0.001);
        assertEquals(99.99, raw.getDoubeClaim(), 0.001);
        assertEquals(true, raw.getBooleanClaim());
    }

    @Test
    public void convertComplexType() {
        final Address address = raw.getAddress();
        assertNotNull(address);
        assertEquals("street", address.getStreet());
        assertEquals(1000, address.getCode().intValue());
    }

    @Produces
    @RequestScoped
    private static JsonWebToken jwt() throws Exception {
        String jwt = Jwt.claims("/token-converter.json").sign();
        JsonWebSignature jws = new JsonWebSignature();
        jws.setKey(KeyUtils.readPublicKey("/publicKey.pem"));
        jws.setCompactSerialization(jwt);
        JwtClaims claims = JwtClaims.parse(jws.getPayload());
        return new DefaultJWTCallerPrincipal(jwt, claims);
    }

    @RequestScoped
    private static class RawConverterBean {
        @Inject
        @Claim("preferred_username")
        private String name;
        @Inject
        @Claim("byte")
        private Byte byteClaim;
        @Inject
        @Claim("short")
        private Short shortClaim;
        @Inject
        @Claim("integer")
        private Integer integerClaim;
        @Inject
        @Claim("float")
        private Float floatClaim;
        @Inject
        @Claim("double")
        private Double doubeClaim;
        @Inject
        @Claim("boolean")
        private Boolean booleanClaim;
        @Inject
        @Claim("long")
        private Long longClaim;
        @Inject
        @Claim("address")
        private Address address;

        String getName() {
            return name;
        }

        public Byte getByteClaim() {
            return byteClaim;
        }

        public Short getShortClaim() {
            return shortClaim;
        }

        public Integer getIntegerClaim() {
            return integerClaim;
        }

        public Float getFloatClaim() {
            return floatClaim;
        }

        public Double getDoubeClaim() {
            return doubeClaim;
        }

        public Boolean getBooleanClaim() {
            return booleanClaim;
        }

        public Long getLongClaim() {
            return longClaim;
        }

        public Address getAddress() {
            return address;
        }
    }

    @RequestScoped
    private static class ClaimConverterBean {
        @Inject
        @Claim("preferred_username")
        private ClaimValue<String> name;

        ClaimValue<String> getName() {
            return name;
        }
    }

    private static class ClaimInjectionBean<T> implements Bean<T>, PassivationCapable {
        private final Class klass;
        private final Converters converters;

        public ClaimInjectionBean(final Class klass) {
            this.klass = klass;
            this.converters = new SmallRyeConvertersBuilder()
                    .withConverter(Address.class, 100,
                            // Jsonb does not support JsonObject to POJO conversion. You need to call toString on it.
                            (Converter<Address>) value -> JsonbBuilder.create().fromJson(value, Address.class))
                    .build();
        }

        @Override
        public Class<?> getBeanClass() {
            return ClaimInjectionBean.class;
        }

        @Override
        public Set<InjectionPoint> getInjectionPoints() {
            return new HashSet<>();
        }

        @Override
        public boolean isNullable() {
            return false;
        }

        @Override
        public T create(final CreationalContext<T> creationalContext) {
            final JsonWebToken jsonWebToken = CDI.current().select(JsonWebToken.class).get();
            if (jsonWebToken == null) {
                return null;
            }

            final BeanManager beanManager = CDI.current().getBeanManager();
            final InjectionPoint injectionPoint = (InjectionPoint) beanManager.getInjectableReference(new InjectionPoint() {
                @Override
                public Type getType() {
                    return InjectionPoint.class;
                }

                @Override
                public Set<Annotation> getQualifiers() {
                    return Collections.<Annotation> singleton(new AnnotationLiteral<Default>() {
                    });
                }

                @Override
                public Bean<?> getBean() {
                    return null;
                }

                @Override
                public Member getMember() {
                    return null;
                }

                @Override
                public Annotated getAnnotated() {
                    return null;
                }

                @Override
                public boolean isDelegate() {
                    return false;
                }

                @Override
                public boolean isTransient() {
                    return false;
                }
            }, creationalContext);

            final String claimName = getClaimName(injectionPoint);
            if (claimName != null) {
                final Object claim = jsonWebToken.getClaim(claimName);
                if (claim == null) {
                    return null;
                }
                return (T) converters.convertValue(claim.toString(), klass);
            }

            return null;
        }

        @Override
        public void destroy(final T instance, final CreationalContext<T> creationalContext) {

        }

        @Override
        public Set<Type> getTypes() {
            return Collections.singleton(klass);
        }

        @Override
        public Set<Annotation> getQualifiers() {
            return Collections.singleton(ClaimLiteral.INSTANCE);
        }

        @Override
        public Class<? extends Annotation> getScope() {
            return Dependent.class;
        }

        @Override
        public String getName() {
            return this.getClass().getName() + "_" + klass;
        }

        @Override
        public Set<Class<? extends Annotation>> getStereotypes() {
            return Collections.emptySet();
        }

        @Override
        public boolean isAlternative() {
            return false;
        }

        @Override
        public String getId() {
            return getName();
        }

        private static String getClaimName(InjectionPoint ip) {
            String name = null;
            for (Annotation ann : ip.getQualifiers()) {
                if (ann instanceof Claim) {
                    Claim claim = (Claim) ann;
                    name = claim.standard() == Claims.UNKNOWN ? claim.value() : claim.standard().name();
                }
            }
            return name;
        }
    }

    private static final class ClaimLiteral extends AnnotationLiteral<Claim> implements Claim {

        public static final ClaimLiteral INSTANCE = new ClaimLiteral();

        private static final long serialVersionUID = 1L;

        @Override
        public String value() {
            return INSTANCE.value();
        }

        @Override
        public Claims standard() {
            return INSTANCE.standard();
        }
    }

    public static class Address {
        private String street;
        private Integer code;

        public String getStreet() {
            return street;
        }

        public void setStreet(final String street) {
            this.street = street;
        }

        public Integer getCode() {
            return code;
        }

        public void setCode(final Integer code) {
            this.code = code;
        }
    }
}
