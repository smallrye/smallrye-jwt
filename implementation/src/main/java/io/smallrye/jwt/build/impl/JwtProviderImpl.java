package io.smallrye.jwt.build.impl;

import io.smallrye.jwt.build.JwtClaimsBuilder;
import io.smallrye.jwt.build.spi.JwtProvider;

/**
 * Default service provider for JWT Claims Builder objects.
 *
 */
public class JwtProviderImpl extends JwtProvider {

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsBuilder claims() {
        return new JwtBuilderImpl();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsBuilder claims(String jsonLocation) {
        return new JwtBuilderImpl(jsonLocation);
    }

}
