package io.smallrye.jwt.build;

import static io.smallrye.jwt.build.JwtSignJwkTest.getVerifiedJws;
import static io.smallrye.jwt.build.JwtSignTest.getConfigSource;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashMap;
import java.util.Map.Entry;

import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwx.HeaderParameterNames;

import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.util.KeyUtils;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.Tuple;
import net.jqwik.api.Tuple.Tuple2;
import net.jqwik.api.lifecycle.AfterTry;
import net.jqwik.api.lifecycle.BeforeContainer;

public class SignatureAlgorithmSettingTest {

    // all the names that can be used without throwing an exception, and their JWKs
    private static final HashMap<String, Tuple2<String, String>> ACCEPTED_NAMES = new HashMap<>();

    @BeforeContainer
    static void setUp() {
        generateAcceptedNames();
    }

    @AfterTry
    void afterTry() {
        var configSource = getConfigSource();
        configSource.setSignatureAlgorithm(null);
        configSource.setSigningKeyLocation("/privateKey.pem");
    }

    @Provide
    static Arbitrary<Entry<String, Tuple2<String, String>>> validNames() {
        return Arbitraries.of(ACCEPTED_NAMES.entrySet()).dontShrink();
    }

    @Property
    void givenAlgorithmHeader_shouldSignClaims(@ForAll("validNames") Entry<String, Tuple2<String, String>> entry)
            throws Exception {
        // given
        var alg = entry.getKey();
        getConfigSource().setSigningKeyLocation(entry.getValue().get1());
        var publicKey = entry.getValue().get2();

        // when
        var jwt = Jwt.claims()
                .issuer("https://issuer.com")
                .jws()
                .header(HeaderParameterNames.ALGORITHM, alg)
                .header("customHeader", "custom-header-value")
                .sign();

        JsonWebSignature jws;
        if (alg.toUpperCase().startsWith("HS")) {
            jws = getVerifiedJws(jwt, KeyUtils.readSigningKey(publicKey, null, SignatureAlgorithm.fromAlgorithm(alg)));
        } else if (publicKey.endsWith(".pem")) {
            jws = getVerifiedJws(jwt, KeyUtils.readPublicKey(publicKey));
        } else {
            var keyContent = KeyUtils.readKeyContent(publicKey);
            jws = getVerifiedJws(jwt, PublicJsonWebKey.Factory.newPublicJwk(keyContent).getPublicKey());
        }
        var claims = JwtClaims.parse(jws.getPayload());

        // then
        assertEquals(4, claims.getClaimsMap().size());
        assertEquals("https://issuer.com", claims.getIssuer());
        assertEquals("custom-header-value", jws.getHeader("customHeader"));
    }

    @Provide
    static Arbitrary<Tuple2<String, String>> invalidNames() {
        return Arbitraries.strings()
                .injectNull(0.0005)
                .filter((s) -> !ACCEPTED_NAMES.containsKey(s))
                .map((s) -> Tuple.of(s, ",/edEcPrivateKey.jwk"));
    }

    @Property
    void givenInvalidAlgorithmHeader_shouldThrowJwtSignatureExceptionOnSign(
            @ForAll("invalidNames") Tuple2<String, String> tuple) {
        // given
        final var alg = tuple.get1();
        getConfigSource().setSigningKeyLocation(tuple.get2());

        // when, then
        assertThrows(JwtSignatureException.class, () -> Jwt.claims()
                .issuer("https://issuer.com")
                .jws()
                .header(HeaderParameterNames.ALGORITHM, alg)
                .header("customHeader", "custom-header-value")
                .sign());
    }

    private static void generateAcceptedNames() {
        for (var alg : SignatureAlgorithm.values()) {
            var name = alg.name().toCharArray();
            switch (alg) {
                case RS256:
                case RS384:
                case RS512:
                case PS256:
                case PS384:
                case PS512:
                    generateAcceptedNamesForAlgorithm(name, 0, Tuple.of("/privateKey.pem", "/publicKey.pem"));
                    break;
                case ES256:
                    generateAcceptedNamesForAlgorithm(name, 0, Tuple.of("/ecPrivateP256Key.jwk", "/ecPublicP256Key.jwk"));
                    break;
                case ES384:
                    generateAcceptedNamesForAlgorithm(name, 0, Tuple.of("/ecPrivateP384Key.jwk", "/ecPublicP384Key.jwk"));
                    break;
                case ES512:
                    generateAcceptedNamesForAlgorithm(name, 0, Tuple.of("/ecPrivateP512Key.jwk", "/ecPublicP512Key.jwk"));
                    break;
                case EDDSA:
                    generateAcceptedNamesForAlgorithm(name, 0, Tuple.of("/edEcPrivateKey.jwk", "/edEcPublicKey.jwk"));
                    break;
                case HS256:
                    generateAcceptedNamesForAlgorithm(name, 0, Tuple.of("/privateKeyHS256.jwk", "/privateKeyHS256.jwk"));
                    break;
                case HS384:
                    generateAcceptedNamesForAlgorithm(name, 0, Tuple.of("/privateKeyHS384.jwk", "/privateKeyHS384.jwk"));
                    break;
                case HS512:
                    generateAcceptedNamesForAlgorithm(name, 0, Tuple.of("/privateKeyHS512.jwk", "/privateKeyHS512.jwk"));
                    break;
            }
        }
    }

    private static void generateAcceptedNamesForAlgorithm(char[] name, int index, Tuple2<String, String> keys) {
        if (index == name.length) {
            ACCEPTED_NAMES.put(new String(name), keys);
        } else if (Character.isLetter(name[index])) {
            name[index] = Character.toUpperCase(name[index]);
            generateAcceptedNamesForAlgorithm(name, index + 1, keys);
            name[index] = Character.toLowerCase(name[index]);
            generateAcceptedNamesForAlgorithm(name, index + 1, keys);
        } else {
            generateAcceptedNamesForAlgorithm(name, index + 1, keys);
        }
    }
}
