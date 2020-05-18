package io.smallrye.jwt.auth.cdi;

import java.lang.annotation.Annotation;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.BeanAttributes;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.enterprise.inject.spi.ProcessBeanAttributes;
import javax.enterprise.inject.spi.ProcessInjectionPoint;
import javax.inject.Provider;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.Claims;

/**
 * Support for {@linkplain Provider} injection points annotated with {@linkplain Claim}.
 */
public class ProviderExtensionSupport {
    /**
     * Replace the general producer method BeanAttributes with one bound to the collected injection site
     * types to properly reflect all of the type locations the producer method applies to.
     *
     * @param pba the ProcessBeanAttributes
     * @see ProviderBeanAttributes
     */
    public void addTypeToClaimProducer(@Observes ProcessBeanAttributes pba) {
        if (!providerOptionalTypes.isEmpty() && pba.getAnnotated().isAnnotationPresent(Claim.class)) {
            Claim claim = pba.getAnnotated().getAnnotation(Claim.class);
            if (claim.value().length() == 0 && claim.standard() == Claims.UNKNOWN) {
                CDILogging.log.addTypeToClaimProducer(pba.getAnnotated());
                BeanAttributes delegate = pba.getBeanAttributes();
                if (delegate.getTypes().contains(Optional.class)) {
                    pba.setBeanAttributes(new ProviderBeanAttributes(delegate, providerOptionalTypes, providerQualifiers));
                }
            }
        }
    }

    /**
     * Collect the types of all {@linkplain Provider} injection points annotated with {@linkplain Claim}.
     *
     * @param pip - the injection point event information
     */
    void processClaimProviderInjections(@Observes ProcessInjectionPoint<?, ? extends Provider> pip) {
        CDILogging.log.pip(pip.getInjectionPoint());
        final InjectionPoint ip = pip.getInjectionPoint();
        if (ip.getAnnotated().isAnnotationPresent(Claim.class)) {
            Claim claim = ip.getAnnotated().getAnnotation(Claim.class);
            if (claim.value().length() == 0 && claim.standard() == Claims.UNKNOWN) {
                pip.addDefinitionError(CDIMessages.msg.claimHasNoNameOrValidStandardEnumSetting(ip));
            }
            boolean usesEnum = claim.standard() != Claims.UNKNOWN;
            final String claimName = usesEnum ? claim.standard().name() : claim.value();
            CDILogging.log.checkingProviderClaim(claimName, ip);
            Type matchType = ip.getType();
            // The T from the Provider<T> injection site
            Type actualType = ((ParameterizedType) matchType).getActualTypeArguments()[0];
            // Don't add Optional or JsonValue as this is handled specially
            if (isOptional(actualType)) {
                // Validate that this is not an Optional<JsonValue>
                Type innerType = ((ParameterizedType) actualType).getActualTypeArguments()[0];
                if (!isJson(innerType)) {
                    providerOptionalTypes.add(actualType);
                    providerQualifiers.add(claim);
                }
            }
        }
    }

    private static boolean isOptional(Type type) {
        return type.getTypeName().startsWith(Optional.class.getTypeName());
    }

    private static boolean isJson(Type type) {
        return type.getTypeName().startsWith("javax.json.Json");
    }

    private Set<Type> providerOptionalTypes = new HashSet<>();
    private Set<Annotation> providerQualifiers = new HashSet<>();

    /**
     * An implementation of BeanAttributes that wraps the generic producer BeanAttributes
     */
    public static class ProviderBeanAttributes implements BeanAttributes<Object> {
        /**
         * Decorate the ConfigPropertyProducer BeanAttributes to set the types the producer applies to. This set is collected
         * from all injection points annotated with @ConfigProperty.
         *
         * @param delegate - the original producer method BeanAttributes
         * @param types - the full set of @Claim injection point types
         * @param qualifiers - @Claim qualifiers
         */
        public ProviderBeanAttributes(BeanAttributes<Object> delegate, Set<Type> types, Set<Annotation> qualifiers) {
            this.delegate = delegate;
            this.types = types;
            this.qualifiers = qualifiers;
        }

        @Override
        public Set<Type> getTypes() {
            return types;
        }

        @Override
        public Set<Annotation> getQualifiers() {
            return qualifiers;
        }

        @Override
        public Class<? extends Annotation> getScope() {
            return delegate.getScope();
        }

        @Override
        public String getName() {
            return delegate.getName();
        }

        @Override
        public Set<Class<? extends Annotation>> getStereotypes() {
            return delegate.getStereotypes();
        }

        @Override
        public boolean isAlternative() {
            return delegate.isAlternative();
        }

        private BeanAttributes<Object> delegate;

        private Set<Type> types;

        private Set<Annotation> qualifiers;

    }
}
