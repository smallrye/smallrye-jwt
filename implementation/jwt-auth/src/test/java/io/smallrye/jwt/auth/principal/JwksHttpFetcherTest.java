/*
 *   Copyright 2026 Red Hat, Inc, and individual contributors.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */
package io.smallrye.jwt.auth.principal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import io.smallrye.jwt.auth.principal.JwksHttpFetcher.Response;

class JwksHttpFetcherTest {

    private static final String JWKS = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"1\",\"k\":\"AAECAwQFBgcICQoLDA0ODw\"}]}";

    private HttpServer server;
    private final AtomicInteger requests = new AtomicInteger();

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.start();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void fetchResponseWithCachingHeaders() throws Exception {
        server.createContext("/jwks", exchange -> {
            exchange.getResponseHeaders().add("Cache-Control", "max-age=300");
            exchange.getResponseHeaders().add("Expires", "Wed, 21 Oct 2026 07:28:00 GMT");
            respond(exchange, 200, JWKS.getBytes(StandardCharsets.UTF_8));
        });

        Response response = fetcher().fetchResponse(location());
        assertEquals(JWKS, response.body);
        assertEquals("max-age=300", response.cacheControl);
        assertEquals(1792567680000L, response.expires);
        assertEquals(1, requests.get());
    }

    @Test
    void charsetIsTakenFromContentType() throws Exception {
        server.createContext("/jwks", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json; charset=ISO-8859-1");
            respond(exchange, 200, "{\"keys\":[],\"note\":\"café\"}".getBytes(StandardCharsets.ISO_8859_1));
        });

        assertEquals("{\"keys\":[],\"note\":\"café\"}", fetcher().fetch(location()));
    }

    @Test
    void non200ResponseIsRetriedAndThenFails() throws Exception {
        server.createContext("/jwks", exchange -> respond(exchange, 500, new byte[0]));

        IOException ex = assertThrows(IOException.class, () -> fetcher().fetch(location()));
        assertTrue(ex.getMessage().contains("Non 200 status code (500"), ex.getMessage());
        // the first attempt and 3 retries
        assertEquals(4, requests.get());
    }

    @Test
    void transientFailureIsRetried() throws Exception {
        server.createContext("/jwks", exchange -> {
            if (requests.get() == 0) {
                respond(exchange, 503, new byte[0]);
            } else {
                respond(exchange, 200, JWKS.getBytes(StandardCharsets.UTF_8));
            }
        });

        assertEquals(JWKS, fetcher().fetch(location()));
        assertEquals(2, requests.get());
    }

    @Test
    void tooLargeResponseFailsWithoutRetry() throws Exception {
        byte[] body = new byte[512 * 1024 + 1];
        Arrays.fill(body, (byte) ' ');
        server.createContext("/jwks", exchange -> respond(exchange, 200, body));

        IOException ex = assertThrows(IOException.class, () -> fetcher().fetch(location()));
        assertTrue(ex.getMessage().contains("More than " + 512 * 1024 + " characters"), ex.getMessage());
        assertEquals(1, requests.get());
    }

    private void respond(HttpExchange exchange, int status, byte[] body) throws IOException {
        requests.incrementAndGet();
        exchange.sendResponseHeaders(status, body.length == 0 ? -1 : body.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(body);
        }
    }

    private String location() {
        return "http://localhost:" + server.getAddress().getPort() + "/jwks";
    }

    private static JwksHttpFetcher fetcher() throws Exception {
        return new JwksHttpFetcher(new JWTAuthContextInfo("http://localhost/jwks", "issuer"));
    }
}
