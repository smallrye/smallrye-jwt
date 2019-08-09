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

import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.inject.Inject;
import javax.json.JsonValue;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.ClaimValue;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.logging.Logger;

import io.smallrye.jwt.JsonUtils;

/**
 * A class that tracks the current validated MP-JWT and associated JsonWebToken via a thread
 * local to provide a @RequestScoped JsonWebToken producer method.
 *
 * It also provides utility methods for access the current JsonWebToken claim values.
 */
@RequestScoped
public class CommonJwtProducer {
    private static Logger log = Logger.getLogger(CommonJwtProducer.class);

    @Inject
    JsonWebToken currentToken;

    /**
     * A utility method for accessing a claim from the current JsonWebToken as a ClaimValue Optional object.
     *
     * @param ip - injection point of the claim
     * @param <T> expected actual type of the claim
     * @return the claim value wrapper object
     */
    public <T> ClaimValue<Optional<T>> generalClaimValueProducer(InjectionPoint ip) {
        String name = getName(ip);
        ClaimValueWrapper<Optional<T>> wrapper = new ClaimValueWrapper<>(name);
        T value = getValue(name, false);
        Optional<T> optValue = Optional.ofNullable(value);
        wrapper.setValue(optValue);
        return wrapper;
    }

    /**
     * Return the indicated claim value as a JsonValue
     *
     * @param ip - injection point of the claim
     * @return a JsonValue wrapper
     */
    public JsonValue generalJsonValueProducer(InjectionPoint ip) {
        String name = getName(ip);
        Object value = getValue(name, false);
        return JsonUtils.wrapValue(value);
    }

    public <T> T getValue(String name, boolean isOptional) {
        if (currentToken == null) {
            log.debugf("getValue(%s), null JsonWebToken", name);
            return null;
        }

        Optional<T> claimValue = currentToken.claim(name);
        if (!isOptional && !claimValue.isPresent()) {
            log.debugf("Failed to find Claim for: %s", name);
        }
        log.debugf("getValue(%s), isOptional=%s, claimValue=%s", name, isOptional, claimValue);
        return claimValue.orElse(null);
    }

    public String getName(InjectionPoint ip) {
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
