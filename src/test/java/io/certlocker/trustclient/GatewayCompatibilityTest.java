package io.certlocker.trustclient;

import com.sun.net.httpserver.HttpServer;
import io.certlocker.trustclient.client.TrustClient;
import io.certlocker.trustclient.exception.TrustClientException;
import io.certlocker.trustclient.oidc.TrustOidcExchange;
import io.certlocker.trustclient.model.token.TokenType;
import org.junit.jupiter.api.Test;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class GatewayCompatibilityTest {
    @Test void bothRouteModesResolveAssignedAssetsAndNeverDowngrade() throws Exception {
        for (boolean legacy : new boolean[]{true, false}) {
            List<String> requests = new ArrayList<>();
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                String path = exchange.getRequestURI().getRawPath();
                requests.add(path);
                String body = path.contains("/token/") ? "{\"secret_id\":\"bound-secret\"}" : "{}";
                int status = path.endsWith("/denied") ? 403 : 200;
                byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(status, bytes.length);
                exchange.getResponseBody().write(bytes);
                exchange.close();
            });
            server.start();
            var builder = TrustClient.builder().url("http://127.0.0.1:" + server.getAddress().getPort())
                    .apiToken("fixture-token").legacyApi(legacy);
            if (!legacy) builder.accountId("acct");
            try (TrustClient client = builder.build()) {
                client.getSecret(null);
                client.getCertificate(null);
                client.getSecret("slash/id");
                assertThrows(TrustClientException.class, () -> client.getSecret("denied"));
                String scope = legacy ? "" : "acct/";
                assertEquals(List.of("/rest/api/v1/token/" + scope + "get/fixture-token",
                        "/rest/api/v1/secret/" + scope + "get/bound-secret",
                        "/rest/api/v1/cert/" + scope + "get/fixture-token",
                        "/rest/api/v1/secret/" + scope + "get/slash%2Fid",
                        "/rest/api/v1/secret/" + scope + "get/denied"), requests);
            } finally { server.stop(0); }
        }
    }

    @Test void oidcAcceptsBothWireNamingConventions() throws Exception {
        for (boolean snake : new boolean[]{true, false}) {
            List<String> bodies = new ArrayList<>();
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/rest/api/v1/oidc/exchange", exchange -> {
                bodies.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
                String response = snake ? "{\"token_id\":\"fixture-token\",\"account_id\":\"acct\"}"
                        : "{\"tokenId\":\"fixture-token\",\"accountId\":\"acct\"}";
                byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, bytes.length);
                exchange.getResponseBody().write(bytes);
                exchange.close();
            });
            server.start();
            try {
                var result = TrustOidcExchange.exchange(URI.create("http://127.0.0.1:" + server.getAddress().getPort()),
                        "synthetic-jwt", TokenType.SECRET);
                assertEquals("fixture-token", result.tokenId());
                assertEquals("acct", result.accountId());
                assertTrue(bodies.getFirst().contains("\"id_token\":\"synthetic-jwt\""));
                assertTrue(bodies.getFirst().contains("\"idToken\":\"synthetic-jwt\""));
                assertTrue(bodies.getFirst().contains("\"token_type\":\"SECRET\""));
            } finally { server.stop(0); }
        }
    }
}
