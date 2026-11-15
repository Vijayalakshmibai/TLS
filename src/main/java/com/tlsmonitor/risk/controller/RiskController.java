package com.tlsmonitor.risk.controller;

import com.tlsmonitor.common.dto.ApiResponse;
import com.tlsmonitor.common.exception.ResourceNotFoundException;
import com.tlsmonitor.risk.entity.RiskAssessment;
import com.tlsmonitor.risk.entity.SecurityFinding;
import com.tlsmonitor.risk.service.RiskAnalyzer;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/risks")
public class RiskController {

    private final RiskAnalyzer riskAnalyzer;

    public RiskController(RiskAnalyzer riskAnalyzer) {
        this.riskAnalyzer = riskAnalyzer;
    }

    @GetMapping("/{websiteId}")
    public ResponseEntity<ApiResponse<RiskAssessment>> getLatestRiskAssessment(@PathVariable Long websiteId) {
        RiskAssessment assessment = riskAnalyzer.getLatestAssessment(websiteId)
                .orElseThrow(() -> new ResourceNotFoundException("No risk assessment found for website ID: " + websiteId));
        return ResponseEntity.ok(ApiResponse.ok(assessment));
    }

    @GetMapping("/findings/{websiteId}")
    public ResponseEntity<ApiResponse<List<SecurityFinding>>> getFindings(@PathVariable Long websiteId) {
        List<SecurityFinding> findings = riskAnalyzer.getFindingsForWebsite(websiteId);
        return ResponseEntity.ok(ApiResponse.ok(findings));
    }
}
