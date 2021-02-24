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

import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;

@RunWith(Parameterized.class)
public class GenerateSecretFromKeyEncryptionAlgoTest {

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        Collection<Object[]> args = new ArrayList<>();
        for (Map.Entry<KeyEncryptionAlgorithm, Integer> e : KeyUtils.KEY_ENCRYPTION_BITS.entrySet()) {
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
        KeyEncryptionAlgorithm algo = KeyEncryptionAlgorithm.fromAlgorithm(algoName);
        SecretKey keySpec = KeyUtils.generateSecretKey(algo);
        assertEquals("AES", keySpec.getAlgorithm());
        assertEquals(keySizeInBits / 8, keySpec.getEncoded().length);
    }
}
