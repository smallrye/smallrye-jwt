package io.smallrye.jwt.build.impl;

import java.util.Map;

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
        return new JwtClaimsBuilderImpl();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsBuilder claims(Map<String, Object> claims) {
        return new JwtClaimsBuilderImpl(claims);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsBuilder claims(String jsonLocation) {
        return new JwtClaimsBuilderImpl(jsonLocation);
    }

}
