package com.tlsmonitor.inspection.tls;

import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inspection.entity.ValidationStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.net.ssl.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

@Component
public class TLSInspector {

    private static final Logger log = LoggerFactory.getLogger(TLSInspector.class);
    private static final int CONNECT_TIMEOUT_MS = 6000;
    private static final int SO_TIMEOUT_MS = 6000;

    private final CertificateExtractor certificateExtractor;
    private final TLSConfigurationScanner configurationScanner;
    private final com.tlsmonitor.inventory.service.WebsiteValidationService validationService;

    public TLSInspector(CertificateExtractor certificateExtractor, TLSConfigurationScanner configurationScanner) {
        this(certificateExtractor, configurationScanner, new com.tlsmonitor.inventory.service.WebsiteValidationService(true));
    }

    @org.springframework.beans.factory.annotation.Autowired
    public TLSInspector(CertificateExtractor certificateExtractor,
                        TLSConfigurationScanner configurationScanner,
                        com.tlsmonitor.inventory.service.WebsiteValidationService validationService) {
        this.certificateExtractor = certificateExtractor;
        this.configurationScanner = configurationScanner;
        this.validationService = validationService != null ? validationService : new com.tlsmonitor.inventory.service.WebsiteValidationService();
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

        InetAddress addr;
        try {
            addr = InetAddress.getByName(domain);
            scanResult.setResolvedIp(addr.getHostAddress());
            if (!validationService.isAllowLoopback() || !addr.isLoopbackAddress()) {
                validationService.validateIPAgainstSSRF(addr);
            }
        } catch (com.tlsmonitor.common.exception.SSRFSecurityException se) {
            scanResult.setConnectionStatus("BLOCKED_SSRF");
            scanResult.setTrustError(se.getMessage());
            scanResult.setResponseTimeMs(System.currentTimeMillis() - startTime);
            return new InspectionOutcome(scanResult, null);
        } catch (Exception e) {
            scanResult.setConnectionStatus("DNS_RESOLUTION_FAILED");
            scanResult.setTrustError("Could not resolve host: " + domain);
            scanResult.setResponseTimeMs(System.currentTimeMillis() - startTime);
            return new InspectionOutcome(scanResult, null);
        }

        // Validate the chain first; hostname validation is performed separately from the captured leaf.
        ValidationStatus trustStatus = ValidationStatus.NOT_EVALUATED;
        ValidationStatus hostnameStatus = ValidationStatus.NOT_EVALUATED;
        String trustErrorMsg = null;
        SSLSession activeSession = null;
        X509Certificate[] certChain = null;
        boolean standardHandshakeCompleted = false;
        boolean captureHandshakeCompleted = false;

        try {
            SSLContext defaultContext = SSLContext.getDefault();
            SSLSocketFactory factory = defaultContext.getSocketFactory();

            try (Socket plainSocket = new Socket()) {
                plainSocket.connect(new InetSocketAddress(addr, port), CONNECT_TIMEOUT_MS);
                try (SSLSocket sslSocket = (SSLSocket) factory.createSocket(plainSocket, domain, port, true)) {
                    sslSocket.setSoTimeout(SO_TIMEOUT_MS);
                    sslSocket.startHandshake();
                    activeSession = sslSocket.getSession();
                    standardHandshakeCompleted = true;
                    trustStatus = ValidationStatus.VALID;

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
            trustErrorMsg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            if (isTrustValidationFailure(e)) {
                trustStatus = ValidationStatus.INVALID;
            }
            log.warn("TLS handshake validation failed for {}: {}", domain, trustErrorMsg);
        } catch (Exception e) {
            trustErrorMsg = "Connection failed: " + e.getMessage();
            log.warn("TLS connection failed for {}: {}", domain, e.getMessage());
        }

        // Retry with a capturing trust manager so a rejected certificate can still be inspected.
        if (certChain == null || certChain.length == 0) {
            try {
                final X509Certificate[][] captured = new X509Certificate[1][];
                SSLContext captiveContext = SSLContext.getInstance("TLS");
                captiveContext.init(null, new TrustManager[]{new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {
                        captured[0] = chain != null ? chain.clone() : null;
                    }
                }}, new java.security.SecureRandom());

                try (Socket plainSocket = new Socket()) {
                    plainSocket.connect(new InetSocketAddress(addr, port), CONNECT_TIMEOUT_MS);
                    try (SSLSocket sslSocket = (SSLSocket) captiveContext.getSocketFactory().createSocket(plainSocket, domain, port, true)) {
                        sslSocket.setSoTimeout(SO_TIMEOUT_MS);
                        sslSocket.startHandshake();
                        captureHandshakeCompleted = true;
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

        if (certChain == null || certChain.length == 0) {
            scanResult.setConnectionStatus("CONNECTION_FAILED");
            scanResult.setTrustError(trustErrorMsg != null ? trustErrorMsg : "No peer certificate was received.");
            scanResult.setTrustValidationStatus(ValidationStatus.NOT_EVALUATED);
            scanResult.setHostnameValidationStatus(ValidationStatus.NOT_EVALUATED);
            scanResult.setResponseTimeMs(System.currentTimeMillis() - startTime);
            return new InspectionOutcome(scanResult, null);
        }

        hostnameStatus = verifyHostname(domain, certChain[0])
                ? ValidationStatus.VALID
                : ValidationStatus.INVALID;
        scanResult.setTrustValidationStatus(trustStatus);
        scanResult.setHostnameValidationStatus(hostnameStatus);
        scanResult.setTrustError(trustErrorMsg);

        if (activeSession != null) {
            scanResult.setTlsVersion(activeSession.getProtocol());
            scanResult.setCipherSuite(activeSession.getCipherSuite());
            scanResult.setConnectionStatus(
                    standardHandshakeCompleted || captureHandshakeCompleted ? "SUCCESS" : "HANDSHAKE_FAILED");
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

        if (configurationScanner.isOutdatedProtocol(scanResult.getTlsVersion())) {
            scanResult.setWeakProtocolDetected(true);
        }

        if (scanResult.getSupportedProtocols() == null || "None Detected".equalsIgnoreCase(scanResult.getSupportedProtocols())) {
            if (scanResult.getTlsVersion() != null) {
                scanResult.setSupportedProtocols(scanResult.getTlsVersion());
            }
        }

        scanResult.setResponseTimeMs(System.currentTimeMillis() - startTime);
        return new InspectionOutcome(scanResult, certDetails);
    }

    private boolean isTrustValidationFailure(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof CertificateException
                    || cause instanceof CertPathBuilderException
                    || cause instanceof CertPathValidatorException) {
                return true;
            }
        }
        return false;
    }

    public boolean verifyHostname(String domain, X509Certificate cert) {
        if (domain == null || cert == null) {
            return false;
        }
        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans != null && !sans.isEmpty()) {
                for (List<?> item : sans) {
                    if (item.size() >= 2 && item.get(1) != null) {
                        String san = item.get(1).toString().trim();
                        if (matchHostname(domain, san)) {
                            return true;
                        }
                    }
                }
                return false;
            }
            // Fallback to CN if no SANs present
            String cn = extractCn(cert);
            return cn != null && matchHostname(domain, cn);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean matchHostname(String host, String pattern) {
        if (host.equalsIgnoreCase(pattern)) {
            return true;
        }
        if (pattern.startsWith("*.")) {
            String suffix = pattern.substring(1);
            int firstDot = host.indexOf('.');
            if (firstDot > 0) {
                String hostSuffix = host.substring(firstDot);
                return hostSuffix.equalsIgnoreCase(suffix);
            }
        }
        return false;
    }

    private String extractCn(X509Certificate cert) {
        try {
            String dn = cert.getSubjectX500Principal().getName();
            for (String part : dn.split(",")) {
                String trimmed = part.trim();
                if (trimmed.toUpperCase().startsWith("CN=")) {
                    return trimmed.substring(3).trim();
                }
            }
        } catch (Exception ignored) {}
        return null;
    }
}
