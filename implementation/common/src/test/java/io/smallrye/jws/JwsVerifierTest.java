package io.smallrye.jws;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.PrivateKey;

import javax.crypto.SecretKey;

import org.junit.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.util.KeyUtils;

public class JwsVerifierTest {

    private static final String SUBJECT = "alice";

    @Test
    public void verifyWithRsaKey() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair(2048);

        String jws = sign(JWSAlgorithm.RS256, "key-1", new RSASSASigner(keyPair.getPrivate()));

        String payload = JwsVerifier.builder(keyPair.getPublic()).algorithm("RS256").build().verify(jws);
        assertTrue(payload.contains("\"sub\":\"alice\""));
    }

    @Test
    public void verifyWithSecretKey() throws Exception {
        SecretKey secretKey = KeyUtils.generateSecretKey(SignatureAlgorithm.HS256);

        String jws = sign(JWSAlgorithm.HS256, null, new MACSigner(secretKey));

        String payload = JwsVerifier.builder(secretKey).algorithm("HS256").build().verify(jws);
        assertTrue(payload.contains("\"sub\":\"alice\""));
    }

    @Test
    public void verifyParsedSequence() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair(2048);

        String sequence = sign(JWSAlgorithm.RS256, "key-1", new RSASSASigner(keyPair.getPrivate()));

        JsonWebSignature jws = JsonWebSignature.parse(sequence);
        assertEquals(sequence, jws.serialized());
        assertEquals("key-1", jws.headers().keyId());
        assertEquals("RS256", jws.headers().algorithm());
        assertEquals(jws.unverifiedPayload(),
                JwsVerifier.builder(keyPair.getPublic()).algorithm("RS256").build().verify(jws));
    }

    @Test
    public void unexpectedSignatureAlgorithm() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair(2048);

        String jws = sign(JWSAlgorithm.RS256, null, new RSASSASigner(keyPair.getPrivate()));

        JwsVerifier verifier = JwsVerifier.builder(keyPair.getPublic()).algorithm("PS256").build();
        JwsException ex = assertThrows(JwsException.class, () -> verifier.verify(jws));
        assertTrue(ex.getMessage().contains("RS256"));
    }

    @Test
    public void invalidSignature() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair(2048);
        KeyPair anotherKeyPair = KeyUtils.generateKeyPair(2048);

        String jws = sign(JWSAlgorithm.RS256, null, new RSASSASigner(keyPair.getPrivate()));

        JwsVerifier verifier = JwsVerifier.builder(anotherKeyPair.getPublic()).algorithm("RS256").build();
        JwsException ex = assertThrows(JwsException.class, () -> verifier.verify(jws));
        assertTrue(ex.getMessage().contains("signature is invalid"));
    }

    @Test
    public void unsupportedVerificationKey() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair(2048);

        String jws = sign(JWSAlgorithm.RS256, null, new RSASSASigner(keyPair.getPrivate()));

        // a private key can not verify a signature
        PrivateKey privateKey = keyPair.getPrivate();
        JwsVerifier verifier = JwsVerifier.builder(privateKey).algorithm("RS256").build();
        assertThrows(JwsException.class, () -> verifier.verify(jws));
    }

    @Test
    public void invalidSequence() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair(2048);
        JwsVerifier verifier = JwsVerifier.builder(keyPair.getPublic()).algorithm("RS256").build();
        assertThrows(JwsException.class, () -> verifier.verify("not-a-jws-sequence"));
    }

    @Test
    public void signatureAlgorithmIsRequired() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair(2048);
        assertThrows(JwsException.class, () -> JwsVerifier.builder(keyPair.getPublic()).build());
    }

    @Test
    public void verificationKeyIsRequired() throws Exception {
        assertThrows(JwsException.class, () -> JwsVerifier.builder(null).algorithm("RS256").build());
    }

    private static String sign(JWSAlgorithm algorithm, String keyId, JWSSigner signer) throws Exception {
        JWSHeader.Builder headers = new JWSHeader.Builder(algorithm);
        if (keyId != null) {
            headers.keyID(keyId);
        }
        SignedJWT signedJWT = new SignedJWT(headers.build(),
                new JWTClaimsSet.Builder().subject(SUBJECT).build());
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }
}
