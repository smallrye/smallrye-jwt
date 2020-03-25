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

import java.util.Optional;

import javax.annotation.Priority;
import javax.enterprise.context.Dependent;
import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Alternative;
import javax.enterprise.inject.Produces;

import org.eclipse.microprofile.jwt.JsonWebToken;

/**
 * Override the default CDI Principal bean to allow the injection of a Principal to be a JsonWebToken
 */
@Priority(1)
@Alternative
@RequestScoped
public class PrincipalProducer {
    private JsonWebToken token;

    public void setJsonWebToken(JsonWebToken token) {
        this.token = token;
    }

    /**
     * The producer method for the current JsonWebToken
     *
     * @return JsonWebToken
     */
    @RequestScoped
    @Produces
    JsonWebToken currentJWTPrincipalOrNull() {
        return token == null ? new NullJsonWebToken() : token;
    }

    @Dependent
    @Produces
    Optional<JsonWebToken> optionalJWTPrincipal() {
        return token != null ? Optional.of(token) : Optional.empty();
    }
}
