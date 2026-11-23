package com.tlsmonitor.testutil;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;

public class TestTlsServer implements AutoCloseable {

    private final HttpsServer server;
    private final int port;

    public TestTlsServer(SSLContext sslContext) throws IOException {
        this.server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        this.server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            @Override
            public void configure(HttpsParameters params) {
                try {
                    params.setNeedClientAuth(false);
                    params.setProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        });

        this.server.createContext("/", exchange -> {
            String response = "OK";
            exchange.sendResponseHeaders(200, response.length());
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response.getBytes());
            }
        });

        this.server.start();
        this.port = this.server.getAddress().getPort();
    }

    public int getPort() {
        return port;
    }

    public String getHost() {
        return "127.0.0.1";
    }

    @Override
    public void close() {
        if (server != null) {
            server.stop(0);
        }
    }
}
