package com.tlsmonitor.inspection.tls;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.net.ssl.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

@Component
public class TLSConfigurationScanner {

    private static final Logger log = LoggerFactory.getLogger(TLSConfigurationScanner.class);

    private static final String[] PROTOCOLS_TO_PROBE = {"TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0"};
    private static final int TIMEOUT_MS = 4000;

    public record ProtocolScanReport(String supportedProtocols, boolean weakProtocolDetected) {}

    public ProtocolScanReport probeProtocols(String host, int port) {
        List<String> supported = new ArrayList<>();
        boolean weakDetected = false;

        for (String protocol : PROTOCOLS_TO_PROBE) {
            boolean isSupported = probeProtocol(host, port, protocol);
            if (isSupported) {
                supported.add(protocol);
                if ("TLSv1.0".equalsIgnoreCase(protocol) || "TLSv1.1".equalsIgnoreCase(protocol)) {
                    weakDetected = true;
                }
            }
        }

        String result = supported.isEmpty() ? "None Detected" : String.join(", ", supported);
        return new ProtocolScanReport(result, weakDetected);
    }

    private boolean probeProtocol(String host, int port, String protocol) {
        try {
            SSLContext sslContext = SSLContext.getInstance(protocol);
            // Use permissive TrustManager ONLY for testing protocol availability so trust failures don't abort protocol probes
            sslContext.init(null, new TrustManager[]{new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                public void checkServerTrusted(X509Certificate[] chain, String authType) {}
            }}, new java.security.SecureRandom());

            SSLSocketFactory factory = sslContext.getSocketFactory();
            try (Socket plainSocket = new Socket()) {
                plainSocket.connect(new InetSocketAddress(host, port), TIMEOUT_MS);
                try (SSLSocket sslSocket = (SSLSocket) factory.createSocket(plainSocket, host, port, true)) {
                    sslSocket.setEnabledProtocols(new String[]{protocol});
                    sslSocket.setSoTimeout(TIMEOUT_MS);
                    sslSocket.startHandshake();
                    return true;
                }
            }
        } catch (Exception e) {
            log.debug("Protocol probe for {} on {}:{} -> not supported ({})", protocol, host, port, e.getMessage());
            return false;
        }
    }
}
