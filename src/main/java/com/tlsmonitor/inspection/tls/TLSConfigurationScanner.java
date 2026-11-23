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

    // Note: Java JSSE uses "TLSv1" for TLS 1.0. Probing array uses JSSE standard names.
    private static final String[] PROTOCOLS_TO_PROBE = {"TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1"};
    private static final int TIMEOUT_MS = 4000;

    public record ProtocolScanReport(String supportedProtocols, boolean weakProtocolDetected) {}

    public record CipherAnalysis(
            String cipherSuite,
            boolean isSupportedByJvm,
            boolean isEnabledByDefault,
            boolean isWeakOrDeprecated,
            String category,
            String status
    ) {}

    public ProtocolScanReport probeProtocols(String host, int port) {
        List<String> supported = new ArrayList<>();
        boolean weakDetected = false;

        for (String protocol : PROTOCOLS_TO_PROBE) {
            boolean isSupported = probeProtocol(host, port, protocol);
            if (isSupported) {
                String displayName = "TLSv1".equalsIgnoreCase(protocol) ? "TLSv1.0" : protocol;
                supported.add(displayName);
                if (isOutdatedProtocol(protocol)) {
                    weakDetected = true;
                }
            }
        }

        String result = supported.isEmpty() ? "None Detected" : String.join(", ", supported);
        return new ProtocolScanReport(result, weakDetected);
    }

    public boolean probeProtocol(String host, int port, String protocol) {
        String jsseProtocol = "TLSv1.0".equalsIgnoreCase(protocol) ? "TLSv1" : protocol;
        try {
            SSLContext sslContext = SSLContext.getInstance(jsseProtocol);
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
                    sslSocket.setEnabledProtocols(new String[]{jsseProtocol});
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

    public boolean isOutdatedProtocol(String protocol) {
        if (protocol == null || protocol.isBlank()) {
            return false;
        }
        String p = protocol.trim().toUpperCase();
        return p.equals("TLSV1") || p.equals("TLSV1.0") || p.equals("TLSV1.1")
                || p.equals("SSLV3") || p.equals("SSLV2") || p.equals("SSLV2HELLO");
    }

    public boolean isCipherSupportedByJvm(String cipherSuite) {
        if (cipherSuite == null || cipherSuite.isBlank()) {
            return false;
        }
        try {
            String[] supported = SSLContext.getDefault().getSupportedSSLParameters().getCipherSuites();
            for (String s : supported) {
                if (s.equalsIgnoreCase(cipherSuite)) {
                    return true;
                }
            }
        } catch (Exception ignored) {}
        return false;
    }

    public boolean isCipherEnabledByDefault(String cipherSuite) {
        if (cipherSuite == null || cipherSuite.isBlank()) {
            return false;
        }
        try {
            String[] enabled = SSLContext.getDefault().getDefaultSSLParameters().getCipherSuites();
            for (String e : enabled) {
                if (e.equalsIgnoreCase(cipherSuite)) {
                    return true;
                }
            }
        } catch (Exception ignored) {}
        return false;
    }

    public CipherAnalysis analyzeCipherSuite(String cipherSuite) {
        if (cipherSuite == null || cipherSuite.isBlank()) {
            return new CipherAnalysis("UNKNOWN", false, false, false, "UNKNOWN", "UNAVAILABLE");
        }

        boolean supported = isCipherSupportedByJvm(cipherSuite);
        boolean enabled = isCipherEnabledByDefault(cipherSuite);
        String upper = cipherSuite.toUpperCase();

        boolean weak = upper.contains("RC4") || upper.contains("3DES") || upper.contains("DES")
                || upper.contains("NULL") || upper.contains("EXPORT") || upper.contains("MD5")
                || upper.contains("CBC");

        String category;
        if (upper.contains("RC4")) category = "RC4";
        else if (upper.contains("3DES") || upper.contains("DES")) category = "DES/3DES";
        else if (upper.contains("NULL")) category = "NULL";
        else if (upper.contains("EXPORT")) category = "EXPORT";
        else if (upper.contains("MD5")) category = "MD5";
        else if (upper.contains("CBC")) category = "CBC";
        else if (upper.contains("GCM") || upper.contains("POLY1305") || upper.contains("CCM")) category = "AEAD";
        else category = "OTHER";

        String status;
        if (!supported) {
            status = "UNAVAILABLE";
        } else if (weak) {
            status = "AVAILABLE_WEAK";
        } else {
            status = "AVAILABLE_SECURE";
        }

        return new CipherAnalysis(cipherSuite, supported, enabled, weak, category, status);
    }
}

