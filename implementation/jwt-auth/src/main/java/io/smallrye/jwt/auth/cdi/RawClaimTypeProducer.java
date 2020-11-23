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
import javax.json.JsonValue;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;

import io.smallrye.jwt.JsonUtils;

public class RawClaimTypeProducer {
    @Inject
    JsonWebToken currentToken;

    @Produces
    @Claim("")
    Set<String> getClaimAsSet(InjectionPoint ip) {
        CDILogging.log.getClaimAsSet(ip);
        if (currentToken == null) {
            return null;
        }

        String name = getName(ip);
        return (Set<String>) JsonUtils.convert(Set.class, currentToken.getClaim(name));
    }

    @Produces
    @Claim("")
    String getClaimAsString(InjectionPoint ip) {
        CDILogging.log.getClaimAsString(ip);
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
        CDILogging.log.getClaimAsLong(ip);
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
        CDILogging.log.getClaimAsDouble(ip);
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

    @Produces
    @Claim("")
    Boolean getClaimAsBoolean(InjectionPoint ip) {
        CDILogging.log.getClaimAsBoolean(ip);
        if (currentToken == null) {
            return null;
        }

        String name = getName(ip);
        Optional<Object> optValue = currentToken.claim(name);
        Boolean returnValue = null;
        if (optValue.isPresent()) {
            Object value = optValue.get();
            if (value instanceof JsonValue) {
                final JsonValue.ValueType valueType = ((JsonValue) value).getValueType();
                if (valueType.equals(JsonValue.ValueType.TRUE)) {
                    returnValue = true;
                } else if (valueType.equals(JsonValue.ValueType.FALSE)) {
                    returnValue = false;
                }
            } else {
                returnValue = Boolean.valueOf(value.toString());
            }
        }
        return returnValue;
    }

    /**
     * Produces a *raw* Optional value.
     *
     * @param ip reference to the injection point
     * @return an optional claim value
     */
    @Produces
    @Claim("")
    @SuppressWarnings("rawtypes")
    public Optional getOptionalValue(InjectionPoint ip) {
        CDILogging.log.getOptionalValue(ip);
        if (currentToken == null) {
            return Optional.empty();
        }
        return currentToken.claim(getName(ip));
    }

    static String getName(InjectionPoint ip) {
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
