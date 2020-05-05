package io.smallrye.jwt.build.impl;

import java.util.LinkedHashMap;
import java.util.Map;

import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;

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

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsBuilder claims(JsonWebToken jwt) {
        Map<String, Object> claims = new LinkedHashMap<>();
        for (String name : jwt.getClaimNames()) {
            if (Claims.raw_token.name().equals(name)) {
                continue;
            }
            claims.put(name, jwt.getClaim(name));
        }
        return claims(claims);
    }

}
