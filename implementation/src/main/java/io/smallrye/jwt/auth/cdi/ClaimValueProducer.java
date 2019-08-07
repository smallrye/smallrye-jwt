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

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Optional;

import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Produces;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.inject.Inject;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.ClaimValue;

/**
 * A producer for the ClaimValue wrapper injection sites.
 * 
 * @param <T> the raw claim type
 */
@Dependent
public class ClaimValueProducer {

    @Inject
    CommonJwtProducer util;

    @Produces
    @Claim("")
    <T> ClaimValue<T> produceClaim(InjectionPoint ip) {
        return new ClaimValueProxy<>(ip);
    }

    private class ClaimValueProxy<T> extends ClaimValueWrapper<T> {
        final boolean optional;

        ClaimValueProxy(InjectionPoint ip) {
            super(util.getName(ip));
            Type injectedType = ip.getType();

            if (injectedType instanceof ParameterizedType) {
                ParameterizedType parameterizedType = (ParameterizedType) injectedType;
                Type typeArgument = parameterizedType.getActualTypeArguments()[0];
                // Check if the injection point is optional, i.e. ClaimValue<<Optional<?>>
                optional = typeArgument.getTypeName().startsWith(Optional.class.getTypeName());
            } else {
                optional = false;
            }
        }

        @Override
        @SuppressWarnings("unchecked")
        public T getValue() {
            Object value = util.getValue(getName(), optional);

            if (optional) {
                /*
                 * Wrap the raw value in Optional based on type parameter of the
                 * ClaimValue checked during construction.
                 */
                return (T) Optional.ofNullable(value);
            }

            return (T) value;
        }
    }
}
