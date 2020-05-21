package io.smallrye.jwt.config;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.util.NoSuchElementException;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.inject.Provider;

import org.eclipse.microprofile.config.ConfigProvider;
import org.jboss.weld.junit4.WeldInitiator;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;

import io.smallrye.config.inject.ConfigExtension;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;

public class JWTAuthContextInfoProviderTest {
    @Rule
    public WeldInitiator weld = WeldInitiator.from(JWTAuthContextInfoProvider.class, ConfigExtension.class)
            .addBeans()
            .activate(RequestScoped.class, ApplicationScoped.class)
            .inject(this)
            .build();

    @Inject
    Provider<JWTAuthContextInfoProvider> context;

    @After
    public void tearDown() throws Exception {
        System.clearProperty("mp.jwt.token.header");
        System.clearProperty("mp.jwt.token.cookie");
        System.clearProperty("mp.jwt.verify.audiences");
        System.clearProperty("smallrye.jwt.token.header");
        System.clearProperty("smallrye.jwt.token.cookie");
        System.clearProperty("smallrye.jwt.verify.aud");
    }

    @Test
    public void cookieConfigs() {
        System.setProperty("mp.jwt.token.header", "Cookie");
        System.setProperty("mp.jwt.token.cookie", "jwt");
        JWTAuthContextInfo contextInfo = context.get().getOptionalContextInfo().get();
        assertEquals("Cookie", contextInfo.getTokenHeader());
        assertEquals("jwt", contextInfo.getTokenCookie());
        assertThrows(NoSuchElementException.class,
                () -> ConfigProvider.getConfig().getValue("smallrye.jwt.token.header", String.class));
        assertThrows(NoSuchElementException.class,
                () -> ConfigProvider.getConfig().getValue("smallrye.jwt.token.cookie", String.class));
    }

    @Test
    public void smallryeCookieConfigs() {
        System.setProperty("smallrye.jwt.token.header", "Cookie");
        System.setProperty("smallrye.jwt.token.cookie", "jwt");
        JWTAuthContextInfo contextInfo = context.get().getOptionalContextInfo().get();
        assertEquals("Cookie", contextInfo.getTokenHeader());
        assertEquals("jwt", contextInfo.getTokenCookie());
        assertThrows(NoSuchElementException.class,
                () -> ConfigProvider.getConfig().getValue("mp.jwt.token.header", String.class));
        assertThrows(NoSuchElementException.class,
                () -> ConfigProvider.getConfig().getValue("mp.jwt.token.cookie", String.class));
    }

    @Test
    public void mixCookieConfigs() {
        System.setProperty("mp.jwt.token.header", "Cookie");
        System.setProperty("smallrye.jwt.token.cookie", "jwt");
        JWTAuthContextInfo contextInfo = context.get().getOptionalContextInfo().get();
        assertEquals("Cookie", contextInfo.getTokenHeader());
        assertEquals("jwt", contextInfo.getTokenCookie());
        assertThrows(NoSuchElementException.class,
                () -> ConfigProvider.getConfig().getValue("smallrye.jwt.token.header", String.class));
        assertThrows(NoSuchElementException.class,
                () -> ConfigProvider.getConfig().getValue("mp.jwt.token.cookie", String.class));
    }

    @Test
    public void audienceConfigs() {
        System.setProperty("mp.jwt.verify.audiences", "1234");
        JWTAuthContextInfo contextInfo = context.get().getOptionalContextInfo().get();
        assertEquals(1, contextInfo.getExpectedAudience().size());
        assertTrue(contextInfo.getExpectedAudience().contains("1234"));
        assertThrows(NoSuchElementException.class,
                () -> ConfigProvider.getConfig().getValue("smallrye.jwt.verify.aud", String.class));
    }

    @Test
    public void smallryeAudienceConfigs() {
        System.setProperty("smallrye.jwt.verify.aud", "1234");
        JWTAuthContextInfo contextInfo = context.get().getOptionalContextInfo().get();
        assertEquals(1, contextInfo.getExpectedAudience().size());
        assertTrue(contextInfo.getExpectedAudience().contains("1234"));
        assertThrows(NoSuchElementException.class,
                () -> ConfigProvider.getConfig().getValue("mp.jwt.verify.audiences", String.class));
    }

    @Test
    public void mpAudienceConfigPriority() {
        System.setProperty("mp.jwt.verify.audiences", "1234");
        System.setProperty("smallrye.jwt.verify.aud", "5678");
        JWTAuthContextInfo contextInfo = context.get().getOptionalContextInfo().get();
        assertEquals(1, contextInfo.getExpectedAudience().size());
        assertTrue(contextInfo.getExpectedAudience().contains("1234"));
    }
}
