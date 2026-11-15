package com.tlsmonitor.alerts.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "alerts")
public class Alert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Long websiteId;

    @Column(nullable = false, length = 255)
    private String domain;

    @Column(nullable = false, length = 50)
    private String alertType; // EXPIRY_WARNING, EXPIRED, CRITICAL_RISK, HOSTNAME_MISMATCH

    @Column(nullable = false, length = 30)
    private String severity; // CRITICAL, HIGH, MEDIUM, INFO

    @Column(nullable = false, length = 1000)
    private String message;

    @Column(nullable = false, length = 30)
    private String status = "PENDING"; // PENDING, SENT, FAILED, RESOLVED, ACKNOWLEDGED

    @Column(nullable = false)
    private LocalDateTime createdAt;

    private LocalDateTime sentAt;
    private LocalDateTime resolvedAt;

    public Alert() {
        this.createdAt = LocalDateTime.now();
        this.status = "PENDING";
    }

    public Alert(Long websiteId, String domain, String alertType, String severity, String message) {
        this.websiteId = websiteId;
        this.domain = domain;
        this.alertType = alertType;
        this.severity = severity;
        this.message = message;
        this.status = "PENDING";
        this.createdAt = LocalDateTime.now();
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

    public String getAlertType() {
        return alertType;
    }

    public void setAlertType(String alertType) {
        this.alertType = alertType;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getSentAt() {
        return sentAt;
    }

    public void setSentAt(LocalDateTime sentAt) {
        this.sentAt = sentAt;
    }

    public LocalDateTime getResolvedAt() {
        return resolvedAt;
    }

    public void setResolvedAt(LocalDateTime resolvedAt) {
        this.resolvedAt = resolvedAt;
    }
}
