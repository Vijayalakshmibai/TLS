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
}
