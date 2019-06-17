package io.smallrye.jwt.auth.jaxrs;

import static java.util.Collections.emptyList;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.UnresolvableKeyException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mock;

import io.smallrye.jwt.auth.principal.KeyLocationResolver;

public class KeyLocationResolverTest {

    @Mock
    JsonWebSignature jsonWebSignature;

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Test
    public void testLoadingPublicKeyWithWrongResourceLocation() throws Exception {

        expectedEx.expect(UnresolvableKeyException.class);

        KeyLocationResolver keyLocationResolver = new KeyLocationResolver("wrong_location.pem");
        keyLocationResolver.resolveKey(jsonWebSignature, emptyList());
    }
}
