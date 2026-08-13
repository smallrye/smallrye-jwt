package io.smallrye.jwt.auth.principal;

import java.security.Key;

import io.smallrye.jwt.auth.JsonWebSignature;
import io.smallrye.jwt.auth.VerificationKeyResolver;

/**
 * A {@link VerificationKeyResolver} that always returns a pre-configured key.
 */
public class SingleKeyVerificationKeyResolver implements VerificationKeyResolver {
    private final Key key;

    public SingleKeyVerificationKeyResolver(Key key) {
        this.key = key;
    }

    @Override
    public Key resolveKey(JsonWebSignature jws) {
        return key;
    }
}
