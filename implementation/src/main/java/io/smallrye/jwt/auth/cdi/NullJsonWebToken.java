package io.smallrye.jwt.auth.cdi;

import java.util.Set;

import org.eclipse.microprofile.jwt.JsonWebToken;

public class NullJsonWebToken implements JsonWebToken {

    @Override
    public String getName() {
        return null;
    }

    @Override
    public Set<String> getClaimNames() {
        return null;
    }

    @Override
    public <T> T getClaim(String claimName) {
        return null;
    }
}
