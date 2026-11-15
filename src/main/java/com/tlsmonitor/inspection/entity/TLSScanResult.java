package com.tlsmonitor.inspection.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "scan_results")
public class TLSScanResult {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Long websiteId;

    @Column(nullable = false)
    private String domain;

    private String resolvedIp;

    private int port = 443;

    @Column(nullable = false, length = 50)
    private String connectionStatus; // SUCCESS, FAILED, TIMEOUT, UNREACHABLE

    private String tlsVersion; // e.g. TLSv1.3
    private String cipherSuite; // e.g. TLS_AES_128_GCM_SHA256

    private boolean hostnameValid;
    private boolean trustChainValid;

    @Column(columnDefinition = "TEXT")
    private String trustError;

    @Column(columnDefinition = "TEXT")
    private String supportedProtocols; // e.g. TLSv1.2, TLSv1.3

    private boolean weakProtocolDetected; // true if TLS 1.0 or 1.1 enabled

    @Column(nullable = false)
    private LocalDateTime scannedAt;

    private long responseTimeMs;

    public TLSScanResult() {
        this.scannedAt = LocalDateTime.now();
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getWebsiteId() {
        return websiteId;
    }

    public void setWebsiteId(Long websiteId) {
        this.websiteId = websiteId;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getResolvedIp() {
        return resolvedIp;
    }

    public void setResolvedIp(String resolvedIp) {
        this.resolvedIp = resolvedIp;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String getConnectionStatus() {
        return connectionStatus;
    }

    public void setConnectionStatus(String connectionStatus) {
        this.connectionStatus = connectionStatus;
    }

    public String getTlsVersion() {
        return tlsVersion;
    }

    public void setTlsVersion(String tlsVersion) {
        this.tlsVersion = tlsVersion;
    }

    public String getCipherSuite() {
        return cipherSuite;
    }

    public void setCipherSuite(String cipherSuite) {
        this.cipherSuite = cipherSuite;
    }

    public boolean isHostnameValid() {
        return hostnameValid;
    }

    public void setHostnameValid(boolean hostnameValid) {
        this.hostnameValid = hostnameValid;
    }

    public boolean isTrustChainValid() {
        return trustChainValid;
    }

    public void setTrustChainValid(boolean trustChainValid) {
        this.trustChainValid = trustChainValid;
    }

    public String getTrustError() {
        return trustError;
    }

    public void setTrustError(String trustError) {
        this.trustError = trustError;
    }

    public String getSupportedProtocols() {
        return supportedProtocols;
    }

    public void setSupportedProtocols(String supportedProtocols) {
        this.supportedProtocols = supportedProtocols;
    }

    public boolean isWeakProtocolDetected() {
        return weakProtocolDetected;
    }

    public void setWeakProtocolDetected(boolean weakProtocolDetected) {
        this.weakProtocolDetected = weakProtocolDetected;
    }

    public LocalDateTime getScannedAt() {
        return scannedAt;
    }

    public void setScannedAt(LocalDateTime scannedAt) {
        this.scannedAt = scannedAt;
    }

    public long getResponseTimeMs() {
        return responseTimeMs;
    }

    public void setResponseTimeMs(long responseTimeMs) {
        this.responseTimeMs = responseTimeMs;
    }
}
