package com.tlsmonitor.inspection.tls;

import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.net.ssl.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;

@Component
public class TLSInspector {

    private static final Logger log = LoggerFactory.getLogger(TLSInspector.class);
    private static final int CONNECT_TIMEOUT_MS = 6000;
    private static final int SO_TIMEOUT_MS = 6000;

    private final CertificateExtractor certificateExtractor;
    private final TLSConfigurationScanner configurationScanner;

    public TLSInspector(CertificateExtractor certificateExtractor, TLSConfigurationScanner configurationScanner) {
        this.certificateExtractor = certificateExtractor;
        this.configurationScanner = configurationScanner;
    }

    public record InspectionOutcome(TLSScanResult scanResult, CertificateDetails certificateDetails) {}

    public InspectionOutcome inspect(Long websiteId, String domain, int port) {
        long startTime = System.currentTimeMillis();

        TLSScanResult scanResult = new TLSScanResult();
        scanResult.setWebsiteId(websiteId);
        scanResult.setDomain(domain);
        scanResult.setPort(port);
        scanResult.setScannedAt(LocalDateTime.now());

        CertificateDetails certDetails = null;

        try {
            InetAddress addr = InetAddress.getByName(domain);
            scanResult.setResolvedIp(addr.getHostAddress());
        } catch (Exception e) {
            scanResult.setConnectionStatus("DNS_RESOLUTION_FAILED");
            scanResult.setTrustError("Could not resolve host: " + domain);
            scanResult.setResponseTimeMs(System.currentTimeMillis() - startTime);
            return new InspectionOutcome(scanResult, null);
        }

        // 1. Primary Handshake using Default JVM TrustStore (Validates Trust & Hostname)
        boolean trustValid = false;
        String trustErrorMsg = null;
        SSLSession activeSession = null;
        X509Certificate[] certChain = null;

        try {
            SSLContext defaultContext = SSLContext.getDefault();
            SSLSocketFactory factory = defaultContext.getSocketFactory();

            try (Socket plainSocket = new Socket()) {
                plainSocket.connect(new InetSocketAddress(domain, port), CONNECT_TIMEOUT_MS);
                try (SSLSocket sslSocket = (SSLSocket) factory.createSocket(plainSocket, domain, port, true)) {
                    sslSocket.setSoTimeout(SO_TIMEOUT_MS);

                    // Enable standard HTTPS endpoint identification for hostname verification
                    SSLParameters params = sslSocket.getSSLParameters();
                    params.setEndpointIdentificationAlgorithm("HTTPS");
                    sslSocket.setSSLParameters(params);

                    sslSocket.startHandshake();
                    activeSession = sslSocket.getSession();
                    trustValid = true;

                    Certificate[] peerCerts = activeSession.getPeerCertificates();
                    if (peerCerts != null && peerCerts.length > 0) {
                        certChain = new X509Certificate[peerCerts.length];
                        for (int i = 0; i < peerCerts.length; i++) {
                            certChain[i] = (X509Certificate) peerCerts[i];
                        }
                    }
                }
            }
        } catch (SSLException e) {
            trustValid = false;
            trustErrorMsg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            log.warn("Trust verification failed for {}: {}", domain, trustErrorMsg);
        } catch (Exception e) {
            scanResult.setConnectionStatus("CONNECTION_FAILED");
            scanResult.setTrustError("Connection failed: " + e.getMessage());
            scanResult.setResponseTimeMs(System.currentTimeMillis() - startTime);
            return new InspectionOutcome(scanResult, null);
        }

        // 2. If trust validation failed or socket threw SSLHandshakeException, connect with captive inspector
        // to retrieve the untrusted/self-signed/expired peer certificate chain so we can inspect and report it!
        if (certChain == null || certChain.length == 0) {
            try {
                final X509Certificate[][] captured = new X509Certificate[1][];
                SSLContext captiveContext = SSLContext.getInstance("TLS");
                captiveContext.init(null, new TrustManager[]{new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {
                        captured[0] = chain;
                    }
                }}, new java.security.SecureRandom());

                try (Socket plainSocket = new Socket()) {
                    plainSocket.connect(new InetSocketAddress(domain, port), CONNECT_TIMEOUT_MS);
                    try (SSLSocket sslSocket = (SSLSocket) captiveContext.getSocketFactory().createSocket(plainSocket, domain, port, true)) {
                        sslSocket.setSoTimeout(SO_TIMEOUT_MS);
                        sslSocket.startHandshake();
                        if (activeSession == null) {
                            activeSession = sslSocket.getSession();
                        }
                        if (captured[0] != null && captured[0].length > 0) {
                            certChain = captured[0];
                        } else {
                            Certificate[] peerCerts = sslSocket.getSession().getPeerCertificates();
                            if (peerCerts != null) {
                                certChain = new X509Certificate[peerCerts.length];
                                for (int i = 0; i < peerCerts.length; i++) {
                                    certChain[i] = (X509Certificate) peerCerts[i];
                                }
                            }
                        }
                    }
                }
            } catch (Exception e) {
                log.warn("Captive certificate inspection failed for {}: {}", domain, e.getMessage());
            }
        }

        // Check Hostname verification independently
        boolean hostnameValid = false;
        if (certChain != null && certChain.length > 0) {
            try {
                HostnameVerifier verifier = HttpsURLConnection.getDefaultHostnameVerifier();
                if (activeSession != null) {
                    hostnameValid = verifier.verify(domain, activeSession);
                }
            } catch (Exception e) {
                hostnameValid = false;
            }
        }

        scanResult.setTrustChainValid(trustValid);
        scanResult.setHostnameValid(hostnameValid);
        scanResult.setTrustError(trustErrorMsg);

        if (activeSession != null) {
            scanResult.setTlsVersion(activeSession.getProtocol());
            scanResult.setCipherSuite(activeSession.getCipherSuite());
            scanResult.setConnectionStatus("SUCCESS");
        } else {
            scanResult.setConnectionStatus("HANDSHAKE_FAILED");
        }

        // 3. Extract Certificate Details
        if (certChain != null && certChain.length > 0) {
            X509Certificate leafCert = certChain[0];
            certDetails = certificateExtractor.extractDetails(leafCert, null, websiteId, certChain.length);
        }

        // 4. Protocol Probing (detect supported protocols & weak TLS 1.0/1.1)
        try {
            TLSConfigurationScanner.ProtocolScanReport report = configurationScanner.probeProtocols(domain, port);
            scanResult.setSupportedProtocols(report.supportedProtocols());
            scanResult.setWeakProtocolDetected(report.weakProtocolDetected());
        } catch (Exception e) {
            scanResult.setSupportedProtocols(scanResult.getTlsVersion());
        }

        scanResult.setResponseTimeMs(System.currentTimeMillis() - startTime);
        return new InspectionOutcome(scanResult, certDetails);
    }
}
