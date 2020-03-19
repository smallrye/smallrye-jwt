package io.smallrye.jwt.tck;

import javax.ws.rs.ext.Provider;

/**
 * This is to register the JAX-RS Feature to add the SmallRye JWT Filters. This cannot be registed as a Provider
 * Service Loader, because it would initialize before the JAX-RS Application is available in the Context. This is
 * required to check the LoginModule in the Application class and provide correct registration of the filters.
 */
@Provider
public class SmallRyeJWTAuthJaxRsFeature extends io.smallrye.jwt.auth.jaxrs.SmallRyeJWTAuthJaxRsFeature {
}
