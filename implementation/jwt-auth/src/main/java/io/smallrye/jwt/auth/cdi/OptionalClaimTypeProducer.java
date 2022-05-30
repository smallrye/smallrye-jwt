package io.smallrye.jwt.auth.cdi;

import static io.smallrye.jwt.auth.cdi.RawClaimTypeProducer.getName;

import java.util.Optional;
import java.util.Set;

import jakarta.enterprise.inject.Produces;
import jakarta.enterprise.inject.spi.InjectionPoint;
import jakarta.inject.Inject;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.JsonWebToken;

import io.smallrye.jwt.JsonUtils;

public class OptionalClaimTypeProducer {
    @Inject
    JsonWebToken currentToken;

    /**
     * Produces an Optional claim value wrapping a String.
     *
     * @param ip reference to the injection point
     * @return an optional claim value
     */
    @Produces
    @Claim("")
    public Optional<String> getOptionalString(InjectionPoint ip) {
        CDILogging.log.getOptionalString(ip);
        if (currentToken == null) {
            return Optional.empty();
        }
        return Optional.ofNullable((String) JsonUtils.convert(String.class, currentToken.getClaim(getName(ip))));
    }

    /**
     * Produces an Optional claim value wrapping a Set of Strings.
     *
     * @param ip reference to the injection point
     * @return an optional claim value
     */
    @Produces
    @Claim("")
    public Optional<Set<String>> getOptionalStringSet(InjectionPoint ip) {
        CDILogging.log.getOptionalStringSet(ip);
        if (currentToken == null) {
            return Optional.empty();
        }
        return Optional.ofNullable((Set) JsonUtils.convert(Set.class, currentToken.getClaim(getName(ip))));
    }

    /**
     * Produces an Optional claim value wrapping a Long.
     *
     * @param ip reference to the injection point
     * @return an optional claim value
     */
    @Produces
    @Claim("")
    public Optional<Long> getOptionalLong(InjectionPoint ip) {
        CDILogging.log.getOptionalLong(ip);
        if (currentToken == null) {
            return Optional.empty();
        }
        return Optional.ofNullable((Long) JsonUtils.convert(Long.class, currentToken.getClaim(getName(ip))));
    }

    /**
     * Produces an Optional claim value wrapping a Boolean.
     *
     * @param ip reference to the injection point
     * @return an optional claim value
     */
    @Produces
    @Claim("")
    public Optional<Boolean> getOptionalBoolean(InjectionPoint ip) {
        CDILogging.log.getOptionalBoolean(ip);
        if (currentToken == null) {
            return Optional.empty();
        }
        return Optional.ofNullable((Boolean) JsonUtils.convert(Boolean.class, currentToken.getClaim(getName(ip))));
    }

}
