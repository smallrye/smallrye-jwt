package io.smallrye.jwt.config;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

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
        System.clearProperty("smallrye.jwt.token.header");
        System.clearProperty("smallrye.jwt.token.cookie");
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
}
