package io.smallrye.jwt.auth.principal;

import java.security.Key;
import java.util.List;

import org.jboss.logging.Logger;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.jose4j.lang.UnresolvableKeyException;

/**
 * A simple VerificationKeyResolver implementation to select a Key from a list if existing JWKs.
 */
class SimpleKeyResolver implements VerificationKeyResolver {

    private static final Logger LOGGER = Logger.getLogger(SimpleKeyResolver.class);

    private final List<JsonWebKey> jsonWebKeys;

    SimpleKeyResolver(List<JsonWebKey> jsonWebKeys) {
        this.jsonWebKeys = jsonWebKeys;
    }

    @Override
    public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext) throws UnresolvableKeyException {
        String kid = getKid(jws);

        if (kid != null) {
            for (JsonWebKey currentJwk : jsonWebKeys) {
                if (kid.equals(currentJwk.getKeyId())) {
                    return PublicJsonWebKey.class.cast(currentJwk).getPublicKey();
                }
            }
        }

        LOGGER.debugf("No suitable JWK for kid=%s", kid);
        return null;
    }

    private static String getKid(JsonWebSignature jws) throws UnresolvableKeyException {
        return jws.getHeaders().getStringHeaderValue(JsonWebKey.KEY_ID_PARAMETER);
    }

}
