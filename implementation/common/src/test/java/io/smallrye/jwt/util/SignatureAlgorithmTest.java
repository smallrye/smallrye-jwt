package io.smallrye.jwt.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.util.Collection;
import java.util.HashSet;

import org.junit.platform.commons.util.StringUtils;

import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.lifecycle.BeforeContainer;

public class SignatureAlgorithmTest {

    // all the names that can be used without throwing exception
    private static final Collection<String> ACCEPTED_NAMES = new HashSet<>();

    @BeforeContainer
    static void setUp() {
        for (var alg : SignatureAlgorithm.values()) {
            generateAcceptedNames(alg.name().toCharArray(), 0);
        }
    }

    @Property
    void givenAlgorithm_shouldGetNonBlankAlgorithmName(@ForAll SignatureAlgorithm algorithm) {
        assertTrue(StringUtils.isNotBlank(algorithm.getAlgorithm()));
    }

    @Provide
    static Arbitrary<String> validNames() {
        return Arbitraries.of(ACCEPTED_NAMES).dontShrink();
    }

    @Property
    void givenValidAlgorithmName_shouldReturnAppropriateAlgorithm(@ForAll("validNames") String name) {
        assertEquals(name.toUpperCase(), SignatureAlgorithm.fromAlgorithm(name).getAlgorithm().toUpperCase());
    }

    @Provide
    static Arbitrary<String> invalidNames() {
        return Arbitraries.strings()
                .injectNull(0.0005)
                .filter((s) -> !ACCEPTED_NAMES.contains(s));
    }

    @Property
    void givenInvalidAlgorithmName_shouldThrowIllegalArgumentException(@ForAll("invalidNames") String name) {
        assertThrows(IllegalArgumentException.class, () -> SignatureAlgorithm.fromAlgorithm(name));
    }

    private static void generateAcceptedNames(char[] name, int index) {
        if (index == name.length) {
            ACCEPTED_NAMES.add(new String(name));
        } else if (Character.isLetter(name[index])) {
            name[index] = Character.toUpperCase(name[index]);
            generateAcceptedNames(name, index + 1);
            name[index] = Character.toLowerCase(name[index]);
            generateAcceptedNames(name, index + 1);
        } else {
            generateAcceptedNames(name, index + 1);
        }
    }
}
