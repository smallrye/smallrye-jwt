package io.smallrye.jwt.auth.principal;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Set;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import io.smallrye.jwt.util.ResourceUtils;

/**
 * HTTP fetcher for remote JWKS endpoints.
 * Handles TLS, proxy, and timeouts. The SSLSocketFactory is created once and reused.
 */
class JwksHttpFetcher {

    private static final int DEFAULT_CONNECT_TIMEOUT = 20000;
    private static final int DEFAULT_READ_TIMEOUT = 20000;

    private final SSLSocketFactory sslSocketFactory;
    private final HostnameVerifier hostnameVerifier;
    private final Proxy proxy;

    JwksHttpFetcher(JWTAuthContextInfo authContextInfo) {
        this.sslSocketFactory = buildSslSocketFactory(authContextInfo);
        this.hostnameVerifier = buildHostnameVerifier(authContextInfo);
        this.proxy = buildProxy(authContextInfo);
    }

    String fetch(String location) throws IOException {
        URL url = new URL(location);
        HttpURLConnection connection;

        if (proxy != null) {
            connection = (HttpURLConnection) url.openConnection(proxy);
        } else {
            connection = (HttpURLConnection) url.openConnection();
        }

        if (connection instanceof HttpsURLConnection) {
            HttpsURLConnection httpsConn = (HttpsURLConnection) connection;
            if (sslSocketFactory != null) {
                httpsConn.setSSLSocketFactory(sslSocketFactory);
            }
            if (hostnameVerifier != null) {
                httpsConn.setHostnameVerifier(hostnameVerifier);
            }
        }

        try {
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(DEFAULT_CONNECT_TIMEOUT);
            connection.setReadTimeout(DEFAULT_READ_TIMEOUT);
            connection.setUseCaches(false);
            connection.setRequestProperty("Cache-Control", "no-cache");

            try (InputStream is = connection.getInputStream()) {
                return new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }
        } finally {
            connection.disconnect();
        }
    }

    private static SSLSocketFactory buildSslSocketFactory(JWTAuthContextInfo authContextInfo) {
        if (authContextInfo.isTlsTrustAll()) {
            try {
                SSLContext sc = SSLContext.getInstance("TLS");
                sc.init(null, new TrustManager[] { new TrustAllX509TrustManager() }, new SecureRandom());
                return sc.getSocketFactory();
            } catch (Exception e) {
                throw new IllegalStateException("Failed to configure TLS trust-all", e);
            }
        }

        X509Certificate tlsCert = loadTlsCertificate(authContextInfo);
        if (tlsCert != null) {
            try {
                KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
                trustStore.load(null, null);
                trustStore.setCertificateEntry("trusted", tlsCert);
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(trustStore);
                SSLContext sc = SSLContext.getInstance("TLS");
                sc.init(null, tmf.getTrustManagers(), null);
                return sc.getSocketFactory();
            } catch (Exception e) {
                throw new IllegalStateException("Failed to configure TLS trusted certificate", e);
            }
        }

        return null;
    }

    private static HostnameVerifier buildHostnameVerifier(JWTAuthContextInfo authContextInfo) {
        if (authContextInfo.isTlsTrustAll()) {
            return new TrustAllHostnameVerifier();
        } else if (authContextInfo.getTlsTrustedHosts() != null) {
            return new TrustedHostsHostnameVerifier(authContextInfo.getTlsTrustedHosts());
        }
        return null;
    }

    private static Proxy buildProxy(JWTAuthContextInfo authContextInfo) {
        if (authContextInfo.getHttpProxyHost() != null) {
            return new Proxy(Proxy.Type.HTTP,
                    new InetSocketAddress(authContextInfo.getHttpProxyHost(), authContextInfo.getHttpProxyPort()));
        }
        return null;
    }

    private static X509Certificate loadTlsCertificate(JWTAuthContextInfo authContextInfo) {
        if (authContextInfo.getTlsCertificate() != null) {
            return AbstractKeyLocationResolver.loadPEMCertificate(authContextInfo.getTlsCertificate());
        } else if (authContextInfo.getTlsCertificatePath() != null) {
            try {
                String content = ResourceUtils.readResource(authContextInfo.getTlsCertificatePath());
                if (content != null) {
                    return AbstractKeyLocationResolver.loadPEMCertificate(content);
                }
            } catch (IOException e) {
                PrincipalLogging.log.failedToRefreshJWKSet(e);
            }
        }
        return null;
    }

    static class TrustAllHostnameVerifier implements HostnameVerifier {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    }

    static class TrustedHostsHostnameVerifier implements HostnameVerifier {
        private final Set<String> hosts;

        TrustedHostsHostnameVerifier(Set<String> hosts) {
            this.hosts = hosts;
        }

        @Override
        public boolean verify(String hostname, SSLSession session) {
            return hosts.contains(hostname);
        }
    }

    static class TrustAllX509TrustManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
