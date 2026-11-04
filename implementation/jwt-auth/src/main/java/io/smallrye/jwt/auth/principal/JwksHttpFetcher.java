package io.smallrye.jwt.auth.principal;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Set;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import io.smallrye.jwt.auth.UnresolvableKeyException;
import io.smallrye.jwt.util.ResourceUtils;
import io.smallrye.jwt.util.ResourceUtils.UrlStreamResolver;

/**
 * HTTP fetcher for remote JWKS endpoints.
 * Handles TLS, proxy, and timeouts. The SSLSocketFactory is created once and reused.
 */
class JwksHttpFetcher {

    private static final int DEFAULT_CONNECT_TIMEOUT = 20000;
    private static final int DEFAULT_READ_TIMEOUT = 20000;
    private static final int RETRIES = 3;
    private static final long INITIAL_RETRY_WAIT_TIME = 180;
    private static final long MAX_RETRY_WAIT_TIME = 8000;
    private static final int RESPONSE_BODY_SIZE_LIMIT = 512 * 1024;

    private final SSLSocketFactory sslSocketFactory;
    private final HostnameVerifier hostnameVerifier;
    private final Proxy proxy;

    JwksHttpFetcher(JWTAuthContextInfo authContextInfo) throws UnresolvableKeyException {
        this(authContextInfo, new UrlStreamResolver());
    }

    JwksHttpFetcher(JWTAuthContextInfo authContextInfo, UrlStreamResolver urlResolver) throws UnresolvableKeyException {
        this.sslSocketFactory = buildSslSocketFactory(authContextInfo, urlResolver);
        this.hostnameVerifier = buildHostnameVerifier(authContextInfo);
        this.proxy = buildProxy(authContextInfo);
    }

    String fetch(String location) throws IOException {
        return fetchResponse(location).body;
    }

    Response fetchResponse(String location) throws IOException {
        int attempts = 0;
        while (true) {
            try {
                return fetchOnce(location);
            } catch (SSLHandshakeException | SSLPeerUnverifiedException | FileNotFoundException
                    | ResponseBodyTooLargeException e) {
                throw e;
            } catch (IOException e) {
                attempts++;
                if (attempts > RETRIES) {
                    throw e;
                }
                try {
                    Thread.sleep(retryWaitTime(attempts));
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw e;
                }
            }
        }
    }

    private static long retryWaitTime(int attempt) {
        double pow = Math.pow(2, attempt - 1);
        long wait = (long) (pow * INITIAL_RETRY_WAIT_TIME);
        return Math.min(wait, MAX_RETRY_WAIT_TIME);
    }

    private Response fetchOnce(String location) throws IOException {
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

            int code = connection.getResponseCode();
            if (code != HttpURLConnection.HTTP_OK) {
                throw new IOException("Non 200 status code (" + code + " " + connection.getResponseMessage()
                        + ") returned from " + url);
            }

            StringWriter writer = new StringWriter();
            try (InputStream is = connection.getInputStream();
                    InputStreamReader reader = new InputStreamReader(is, getCharset(connection))) {
                char[] buffer = new char[1024];
                int total = 0;
                int n;
                while ((n = reader.read(buffer)) != -1) {
                    total += n;
                    if (total > RESPONSE_BODY_SIZE_LIMIT) {
                        throw new ResponseBodyTooLargeException("More than " + RESPONSE_BODY_SIZE_LIMIT
                                + " characters have been read from the response body of " + url);
                    }
                    writer.write(buffer, 0, n);
                }
            }
            return new Response(writer.toString(), connection.getHeaderField("Cache-Control"),
                    connection.getHeaderFieldDate("Expires", 0));
        } finally {
            connection.disconnect();
        }
    }

    private static Charset getCharset(HttpURLConnection connection) {
        String contentType = connection.getHeaderField("Content-Type");
        if (contentType != null) {
            for (String part : contentType.replace(" ", "").split(";")) {
                if (part.regionMatches(true, 0, "charset=", 0, 8)) {
                    try {
                        return Charset.forName(part.substring(8));
                    } catch (Exception e) {
                        break;
                    }
                }
            }
        }
        return StandardCharsets.UTF_8;
    }

    /**
     * Response body and the HTTP caching headers which may be used to determine the JWK set cache life.
     */
    static class Response {
        final String body;
        // raw 'Cache-Control' header value, null if absent
        final String cacheControl;
        // 'Expires' header value in milliseconds since the epoch, 0 if absent or unparseable
        final long expires;

        Response(String body, String cacheControl, long expires) {
            this.body = body;
            this.cacheControl = cacheControl;
            this.expires = expires;
        }
    }

    private static class ResponseBodyTooLargeException extends IOException {
        ResponseBodyTooLargeException(String message) {
            super(message);
        }
    }

    private static SSLSocketFactory buildSslSocketFactory(JWTAuthContextInfo authContextInfo,
            UrlStreamResolver urlResolver) throws UnresolvableKeyException {
        // 'trust-all' only relaxes the hostname verification, the certificates are still validated
        X509Certificate tlsCert = loadTlsCertificate(authContextInfo, urlResolver);
        if (tlsCert == null
                && (authContextInfo.getTlsCertificate() != null || authContextInfo.getTlsCertificatePath() != null)) {
            // Do not silently fall back to the default trust store
            throw PrincipalMessages.msg.failedToLoadTlsCertificate(null);
        }
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
                throw PrincipalMessages.msg.failedToLoadTlsCertificate(e);
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

    private static X509Certificate loadTlsCertificate(JWTAuthContextInfo authContextInfo, UrlStreamResolver urlResolver)
            throws UnresolvableKeyException {
        if (authContextInfo.getTlsCertificate() != null) {
            return AbstractKeyLocationResolver.loadPEMCertificate(authContextInfo.getTlsCertificate());
        } else if (authContextInfo.getTlsCertificatePath() != null) {
            try {
                String content = ResourceUtils.readResource(authContextInfo.getTlsCertificatePath(), urlResolver);
                if (content != null) {
                    return AbstractKeyLocationResolver.loadPEMCertificate(content);
                }
            } catch (IOException e) {
                throw PrincipalMessages.msg.failedToLoadTlsCertificate(e);
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
}
