/**
 * Copyright 2018 Red Hat, Inc, and individual contributors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.smallrye.jwt.auth.jaxrs;

import javax.ws.rs.ForbiddenException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Response;

/**
 * @author Michal Szynkiewicz, michal.l.szynkiewicz@gmail.com
 * <br>
 * Date: 6/13/18
 */
public class JWTAuthRequestFailer {

    private JWTAuthRequestFailer() {
    }

    public static void fail(ContainerRequestContext requestContext) {
        if (requestContext.getSecurityContext().getUserPrincipal() == null) {
            throw new NotAuthorizedException("Bearer");
            //respond(requestContext, 401, "Not authorized");
        } else {
            throw new ForbiddenException();
            //respond(requestContext, 403, "Access forbidden: role not allowed");
        }
    }

    @SuppressWarnings("unused")
    private static void respond(ContainerRequestContext context, int status, String message) {
        Response response = Response.status(status)
                .entity(message)
                .type("text/html;charset=UTF-8")
                .build();
        context.abortWith(response);
    }
}
