/*
 *   Copyright 2019 Red Hat, Inc, and individual contributors.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */

package io.smallrye.jwt.auth.cdi;

import java.lang.annotation.Annotation;
import java.util.Optional;
import java.util.Set;

import javax.enterprise.inject.Produces;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.inject.Inject;
import javax.json.JsonNumber;
import javax.json.JsonString;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.logging.Logger;

public class RawClaimTypeProducer {
    private static Logger log = Logger.getLogger(RawClaimTypeProducer.class);

    @Inject
    JsonWebToken currentToken;

    @Produces
    @Claim("")
    Set<String> getClaimAsSet(InjectionPoint ip) {
        log.debugf("getClaimAsSet(%s)", ip);
        if (currentToken == null) {
            return null;
        }

        String name = getName(ip);
        Optional<Set<String>> value = currentToken.claim(name);
        return value.orElse(null);
    }

    @Produces
    @Claim("")
    String getClaimAsString(InjectionPoint ip) {
        log.debugf("getClaimAsString(%s)", ip);
        if (currentToken == null) {
            return null;
        }

        String name = getName(ip);
        Optional<Object> optValue = currentToken.claim(name);
        String returnValue = null;
        if (optValue.isPresent()) {
            Object value = optValue.get();
            if (value instanceof JsonString) {
                JsonString jsonValue = (JsonString) value;
                returnValue = jsonValue.getString();
            } else {
                returnValue = value.toString();
            }
        }
        return returnValue;
    }

    @Produces
    @Claim("")
    Long getClaimAsLong(InjectionPoint ip) {
        log.debugf("getClaimAsLong(%s)", ip);
        if (currentToken == null) {
            return null;
        }

        String name = getName(ip);
        Optional<Object> optValue = currentToken.claim(name);
        Long returnValue = null;
        if (optValue.isPresent()) {
            Object value = optValue.get();
            if (value instanceof JsonNumber) {
                JsonNumber jsonValue = (JsonNumber) value;
                returnValue = jsonValue.longValue();
            } else {
                returnValue = Long.parseLong(value.toString());
            }
        }
        return returnValue;
    }

    @Produces
    @Claim("")
    Double getClaimAsDouble(InjectionPoint ip) {
        log.debugf("getClaimAsDouble(%s)", ip);
        if (currentToken == null) {
            return null;
        }

        String name = getName(ip);
        Optional<Object> optValue = currentToken.claim(name);
        Double returnValue = null;
        if (optValue.isPresent()) {
            Object value = optValue.get();
            if (value instanceof JsonNumber) {
                JsonNumber jsonValue = (JsonNumber) value;
                returnValue = jsonValue.doubleValue();
            } else {
                returnValue = Double.parseDouble(value.toString());
            }
        }
        return returnValue;
    }

    /**
     * Produces a *raw* Optional value.
     *
     * This raw producer is not really required as the MicroProfile JWT specification only requires support for wrappers around
     * the specified typed, however SmallRye JWT has contained this producer in prior releases so existing applications may
     * depend on it.
     *
     * @param ip reference to the injection point
     * @return an optional claim value
     */
    @Produces
    @Claim("")
    @SuppressWarnings("rawtypes")
    public Optional getOptionalValue(InjectionPoint ip) {
        log.debugf("getOptionalValue(%s)", ip);
        if (currentToken == null) {
            return Optional.empty();
        }
        return currentToken.claim(getName(ip));
    }

    /**
     * Produces an Optional claim value wrapping a String.
     *
     * @param ip reference to the injection point
     * @return an optional claim value
     */
    @Produces
    @Claim("")
    public Optional<String> getOptionalString(InjectionPoint ip) {
        log.debugf("getOptionalString(%s)", ip);
        if (currentToken == null) {
            return Optional.empty();
        }
        return currentToken.claim(getName(ip));
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
        log.debugf("getOptionalStringSet(%s)", ip);
        if (currentToken == null) {
            return Optional.empty();
        }
        return currentToken.claim(getName(ip));
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
        log.debugf("getOptionalLong(%s)", ip);
        if (currentToken == null) {
            return Optional.empty();
        }
        return currentToken.claim(getName(ip));
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
        log.debugf("getOptionalBoolean(%s)", ip);
        if (currentToken == null) {
            return Optional.empty();
        }
        return currentToken.claim(getName(ip));
    }

    String getName(InjectionPoint ip) {
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
