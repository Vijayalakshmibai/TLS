package com.tlsmonitor.risk.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "security_findings")
public class SecurityFinding {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Long scanId;

    @Column(nullable = false)
    private Long websiteId;

    @Column(nullable = false, length = 50)
    private String ruleCode; // e.g. EXP_01, HOST_01, TRUST_01, PROTO_01

    @Column(nullable = false, length = 255)
    private String title;

    @Column(length = 1000)
    private String description;

    @Column(nullable = false, length = 30)
    private String severity; // LOW, MEDIUM, HIGH, CRITICAL

    private int points; // Points contributing to risk score

    @Column(length = 1000)
    private String evidence;

    @Column(length = 1000)
    private String recommendation;

    private LocalDateTime createdAt;

    public SecurityFinding() {
        this.createdAt = LocalDateTime.now();
    }

    public SecurityFinding(Long scanId, Long websiteId, String ruleCode, String title,
                           String description, String severity, int points, String evidence, String recommendation) {
        this.scanId = scanId;
        this.websiteId = websiteId;
        this.ruleCode = ruleCode;
        this.title = title;
        this.description = description;
        this.severity = severity;
        this.points = points;
        this.evidence = evidence;
        this.recommendation = recommendation;
        this.createdAt = LocalDateTime.now();
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getScanId() {
        return scanId;
    }

    public void setScanId(Long scanId) {
        this.scanId = scanId;
    }

    public Long getWebsiteId() {
        return websiteId;
    }

    public void setWebsiteId(Long websiteId) {
        this.websiteId = websiteId;
    }

    public String getRuleCode() {
        return ruleCode;
    }

    public void setRuleCode(String ruleCode) {
        this.ruleCode = ruleCode;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public int getPoints() {
        return points;
    }

    public void setPoints(int points) {
        this.points = points;
    }

    public String getEvidence() {
        return evidence;
    }

    public void setEvidence(String evidence) {
        this.evidence = evidence;
    }

    public String getRecommendation() {
        return recommendation;
    }

    public void setRecommendation(String recommendation) {
        this.recommendation = recommendation;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }
}
