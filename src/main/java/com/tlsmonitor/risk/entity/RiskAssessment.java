package com.tlsmonitor.risk.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "risk_assessments")
public class RiskAssessment {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Long scanId;

    @Column(nullable = false)
    private Long websiteId;

    @Column(nullable = false)
    private int totalScore; // 0 - 100

    @Column(nullable = false, length = 30)
    private String riskLevel; // LOW, MEDIUM, HIGH, CRITICAL

    private int findingsCount;

    private String ruleSetVersion = "1.0";

    @Column(nullable = false)
    private LocalDateTime assessedAt;

    public RiskAssessment() {
        this.assessedAt = LocalDateTime.now();
    }

    public RiskAssessment(Long scanId, Long websiteId, int totalScore, String riskLevel, int findingsCount) {
        this.scanId = scanId;
        this.websiteId = websiteId;
        this.totalScore = totalScore;
        this.riskLevel = riskLevel;
        this.findingsCount = findingsCount;
        this.ruleSetVersion = "1.0";
        this.assessedAt = LocalDateTime.now();
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

    public int getTotalScore() {
        return totalScore;
    }

    public void setTotalScore(int totalScore) {
        this.totalScore = totalScore;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    public int getFindingsCount() {
        return findingsCount;
    }

    public void setFindingsCount(int findingsCount) {
        this.findingsCount = findingsCount;
    }

    public String getRuleSetVersion() {
        return ruleSetVersion;
    }

    public void setRuleSetVersion(String ruleSetVersion) {
        this.ruleSetVersion = ruleSetVersion;
    }

    public LocalDateTime getAssessedAt() {
        return assessedAt;
    }

    public void setAssessedAt(LocalDateTime assessedAt) {
        this.assessedAt = assessedAt;
    }
}
