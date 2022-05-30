package io.smallrye.jwt.config;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.InputStream;
import java.util.Base64;
import java.util.Collections;
import java.util.Optional;
import java.util.Scanner;

import jakarta.enterprise.inject.spi.DeploymentException;

import org.junit.Before;
import org.junit.Test;

import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.util.ResourceUtils;

public class JWTAuthContextInfoProviderTest {

    private static final String TEST_ISS = "http://www.example.com/issuer";
    String signerKeyJwk;
    String signerKeyPem;

    @Before
    public void setUp() throws Exception {
        try (InputStream keyStream = getClass().getResourceAsStream("/signer-key4k.jwk");
                Scanner scanner = new Scanner(keyStream)) {
            scanner.useDelimiter("\\A");
            signerKeyJwk = scanner.hasNext() ? Base64.getEncoder().encodeToString(scanner.next().getBytes()) : null;
        }

        try (InputStream keyStream = getClass().getResourceAsStream("/publicKey4k.pem");
                Scanner scanner = new Scanner(keyStream)) {
            scanner.useDelimiter("\\A");
            signerKeyPem = scanner.hasNext() ? scanner.next() : null;
        }
    }

    @Test
    public void testDefaultGetOptionalContextInfo() {
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider.createWithKeyLocation("NONE", TEST_ISS);
        Optional<JWTAuthContextInfo> info = provider.getOptionalContextInfo();
        assertNotNull(info);
        assertTrue(info.isPresent());
    }

    @Test
    public void testDefaultGetContextInfo() {
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider.createWithKeyLocation("NONE", TEST_ISS);
        assertNotNull(provider.getContextInfo());
    }

    @Test
    public void testGetContextInfoWithHttpsKeyLocation() {
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider.createWithKeyLocation("https://publicKey.pem",
                TEST_ISS);
        JWTAuthContextInfo info = provider.getContextInfo();
        assertNull(info.getPublicKeyContent());
        assertEquals("https://publicKey.pem", info.getPublicKeyLocation());
    }

    @Test
    public void testGetContextInfoWithClasspathKeyLocation() throws Exception {
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider.createWithKeyLocation("classpath:publicKey.pem",
                TEST_ISS);
        JWTAuthContextInfo info = provider.getContextInfo();
        assertNull(info.getPublicKeyLocation());
        assertEquals(ResourceUtils.readResource("classpath:publicKey.pem"), info.getPublicKeyContent());
    }

    @Test(expected = DeploymentException.class)
    public void testGetContextInfoWithInvalidClasspathKeyLocation() throws Exception {
        JWTAuthContextInfoProvider.createWithKeyLocation("classpath:publicKeys.pem", TEST_ISS).getContextInfo();
    }

    @Test
    public void testGetOptionalContextInfoWithJwkKey() throws Exception {
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider.createWithKey(signerKeyJwk, TEST_ISS);
        Optional<JWTAuthContextInfo> info = provider.getOptionalContextInfo();
        assertNotNull(info);
        assertTrue(info.isPresent());
        assertNull(info.get().getPublicKeyLocation());
        assertEquals(signerKeyJwk, info.get().getPublicKeyContent());
    }

    @Test
    public void testGetOptionalContextInfoWithPemKey() throws Exception {
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider.createWithKey(signerKeyPem, TEST_ISS);
        Optional<JWTAuthContextInfo> info = provider.getOptionalContextInfo();
        assertNotNull(info);
        assertTrue(info.isPresent());
        assertEquals(signerKeyPem, info.get().getPublicKeyContent());
    }

    @Test
    public void testGetOptionalContextInfoWithExpectedAud() throws Exception {
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider.createWithKey(signerKeyPem, TEST_ISS);
        provider.expectedAudience = Optional.of(Collections.singleton("expected.aud"));
        Optional<JWTAuthContextInfo> info = provider.getOptionalContextInfo();
        assertNotNull(info);
        assertTrue(info.isPresent());
        assertNotNull(info.get().getExpectedAudience());
        assertEquals(1, info.get().getExpectedAudience().size());
        assertEquals("expected.aud", info.get().getExpectedAudience().stream().findFirst().get());
    }

    @Test
    public void testGetOptionalContextInfoWithMaxTimeToLive() throws Exception {
        JWTAuthContextInfoProvider provider = JWTAuthContextInfoProvider.createWithKey(signerKeyPem, TEST_ISS);
        provider.maxTimeToLiveSecs = Optional.of(60L); // 60 seconds
        Optional<JWTAuthContextInfo> info = provider.getOptionalContextInfo();
        assertNotNull(info);
        assertTrue(info.isPresent());
        assertNotNull(info.get().getMaxTimeToLiveSecs());
        assertEquals(Long.valueOf(60L), info.get().getMaxTimeToLiveSecs());
    }
}
