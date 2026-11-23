package com.tlsmonitor.risk.service;

import com.tlsmonitor.risk.entity.SecurityFinding;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RiskScoringService {

    public int calculateScore(List<SecurityFinding> findings) {
        if (findings == null || findings.isEmpty()) {
            return 0;
        }
        int total = findings.stream().mapToInt(SecurityFinding::getPoints).sum();
        return Math.min(total, 100);
    }

    public String determineRiskLevel(int score) {
        if (score >= 70) {
            return "CRITICAL";
        } else if (score >= 40) {
            return "HIGH";
        } else if (score >= 20) {
            return "MEDIUM";
        } else {
            return "LOW";
        }
    }

    public String determineRiskLevel(int score, List<SecurityFinding> findings) {
        String baseLevel = determineRiskLevel(score);
        if (findings == null || findings.isEmpty()) {
            return baseLevel;
        }

        boolean hasCritical = findings.stream().anyMatch(f -> "CRITICAL".equalsIgnoreCase(f.getSeverity()));
        if (hasCritical) {
            return "CRITICAL";
        }

        boolean hasHigh = findings.stream().anyMatch(f -> "HIGH".equalsIgnoreCase(f.getSeverity()));
        if (hasHigh && ("LOW".equalsIgnoreCase(baseLevel) || "MEDIUM".equalsIgnoreCase(baseLevel))) {
            return "HIGH";
        }

        boolean hasMedium = findings.stream().anyMatch(f -> "MEDIUM".equalsIgnoreCase(f.getSeverity()));
        if (hasMedium && "LOW".equalsIgnoreCase(baseLevel)) {
            return "MEDIUM";
        }

        return baseLevel;
    }
}
