package io.smallrye.jwt.util;

import static org.junit.Assert.assertEquals;

import java.security.InvalidAlgorithmParameterException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import javax.crypto.SecretKey;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import io.smallrye.jwt.algorithm.SignatureAlgorithm;

@RunWith(Parameterized.class)
public class GenerateSecretFromSignatureAlgoTest {

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        Collection<Object[]> args = new ArrayList<>();
        for (Map.Entry<SignatureAlgorithm, Integer> e : KeyUtils.SIGNATURE_ALGORITHM_BITS.entrySet()) {
            args.add(new Object[] { e.getKey().getAlgorithm(), e.getValue() });
        }
        return args;
    }

    @Parameterized.Parameter
    public String algoName;

    @Parameterized.Parameter(1)
    public Integer keySizeInBits;

    @Test
    public void givenSymmetricAlgo_thenReturnSecretKey() throws InvalidAlgorithmParameterException {
        SignatureAlgorithm algo = SignatureAlgorithm.fromAlgorithm(algoName);
        SecretKey keySpec = KeyUtils.generateSecretKey(algo);
        assertEquals("HMAC", keySpec.getAlgorithm());
        assertEquals(keySizeInBits / 8, keySpec.getEncoded().length);
    }

}
