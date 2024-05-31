package io.smallrye.jwt.build;

import static io.smallrye.jwt.algorithm.SignatureAlgorithm.EDDSA;
import static io.smallrye.jwt.algorithm.SignatureAlgorithm.ES256;
import static io.smallrye.jwt.algorithm.SignatureAlgorithm.ES384;
import static io.smallrye.jwt.algorithm.SignatureAlgorithm.ES512;
import static io.smallrye.jwt.algorithm.SignatureAlgorithm.HS256;
import static io.smallrye.jwt.algorithm.SignatureAlgorithm.HS384;
import static io.smallrye.jwt.algorithm.SignatureAlgorithm.HS512;
import static io.smallrye.jwt.algorithm.SignatureAlgorithm.PS256;
import static io.smallrye.jwt.algorithm.SignatureAlgorithm.PS384;
import static io.smallrye.jwt.algorithm.SignatureAlgorithm.PS512;
import static io.smallrye.jwt.algorithm.SignatureAlgorithm.RS256;
import static io.smallrye.jwt.algorithm.SignatureAlgorithm.RS384;
import static io.smallrye.jwt.algorithm.SignatureAlgorithm.RS512;
import static io.smallrye.jwt.build.JwtSignJwkTest.getVerifiedJws;
import static io.smallrye.jwt.build.JwtSignTest.getConfigSource;
import static java.util.Map.Entry;
import static java.util.Map.entry;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashMap;
import java.util.Map;

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

    private static final Map<SignatureAlgorithm, Tuple2<String, String>> ALGORITHMS = Map.ofEntries(
            entry(RS256, Tuple.of("/privateKey.pem", "/publicKey.pem")),
            entry(RS384, Tuple.of("/privateKey.pem", "/publicKey.pem")),
            entry(RS512, Tuple.of("/privateKey.pem", "/publicKey.pem")),
            entry(ES256, Tuple.of("/ecPrivateP256Key.jwk", "/ecPublicP256Key.jwk")),
            entry(ES384, Tuple.of("/ecPrivateP384Key.jwk", "/ecPublicP384Key.jwk")),
            entry(ES512, Tuple.of("/ecPrivateP512Key.jwk", "/ecPublicP512Key.jwk")),
            entry(EDDSA, Tuple.of("/edEcPrivateKey.jwk", "/edEcPublicKey.jwk")),
            entry(HS256, Tuple.of("/privateKeyHS256.jwk", "/privateKeyHS256.jwk")),
            entry(HS384, Tuple.of("/privateKeyHS384.jwk", "/privateKeyHS384.jwk")),
            entry(HS512, Tuple.of("/privateKeyHS512.jwk", "/privateKeyHS512.jwk")),
            entry(PS256, Tuple.of("/privateKey.pem", "/publicKey.pem")),
            entry(PS384, Tuple.of("/privateKey.pem", "/publicKey.pem")),
            entry(PS512, Tuple.of("/privateKey.pem", "/publicKey.pem")));

    // all the names that can be used without throwing an exception, and their JWKs
    private static final HashMap<String, Tuple2<String, String>> ACCEPTED_NAMES = new HashMap<>();

    @BeforeContainer
    static void setUp() {
        for (var entry : ALGORITHMS.entrySet()) {
            generateAcceptedNamesForAlgorithm(entry.getKey().name().toCharArray(), 0, entry.getValue());
        }
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

    @Provide
    static Arbitrary<Entry<SignatureAlgorithm, Tuple2<String, String>>> algorithms() {
        return Arbitraries.of(ALGORITHMS.entrySet()).dontShrink();
    }

    @Property
    void givenAlgorithm_shouldSignClaims(@ForAll("algorithms") Entry<SignatureAlgorithm, Tuple2<String, String>> entry)
            throws Exception {
        // given
        var alg = entry.getKey();
        getConfigSource().setSigningKeyLocation(entry.getValue().get1());
        var publicKey = entry.getValue().get2();

        // when
        var jwt = Jwt.claims()
                .issuer("https://issuer.com")
                .jws()
                .algorithm(alg)
                .header("customHeader", "custom-header-value")
                .sign();

        JsonWebSignature jws;
        if (alg.name().toUpperCase().startsWith("HS")) {
            jws = getVerifiedJws(jwt, KeyUtils.readSigningKey(publicKey, null, alg));
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
