package io.smallrye.jwt.util;

import java.security.InvalidAlgorithmParameterException;

import javax.crypto.SecretKey;

import org.junit.Test;

import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;

public class KeyUtilsTest {

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void givenAsymmetricKeyEncryptionAlgo_thenThrowsInvalidAlgorithmException()
            throws InvalidAlgorithmParameterException {
        SecretKey keySpec = KeyUtils.generateSecretKey(KeyEncryptionAlgorithm.RSA_OAEP);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void givenAsymmetricSignatureAlgo_thenThrowsInvalidAlgorithmException() throws InvalidAlgorithmParameterException {
        SecretKey keySpec = KeyUtils.generateSecretKey(SignatureAlgorithm.RS256);
    }
}
