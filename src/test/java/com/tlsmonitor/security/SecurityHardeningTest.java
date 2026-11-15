package com.tlsmonitor.security;

import com.tlsmonitor.common.exception.SSRFSecurityException;
import com.tlsmonitor.inventory.service.WebsiteValidationService;
import com.tlsmonitor.reporting.service.ExcelReportService;
import com.tlsmonitor.risk.entity.SecurityFinding;
import com.tlsmonitor.risk.service.RiskScoringService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Phase 11: Security Hardening & Vulnerability Review Tests")
class SecurityHardeningTest {

    private WebsiteValidationService validationService;
    private RiskScoringService riskScoringService;
    private ExcelReportService excelReportService;

    @BeforeEach
    void setUp() {
        validationService = new WebsiteValidationService();
        riskScoringService = new RiskScoringService();
        excelReportService = new ExcelReportService();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "localhost",
            "127.0.0.1",
            "::1",
            "[::1]",
            "https://127.0.0.1:443",
            "http://localhost:8080",
            "10.0.0.1",
            "10.254.254.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.1.100",
            "169.254.169.254", // Cloud Metadata endpoint
            "metadata.google.internal",
            "service.local",
            "backend.internal"
    })
    @DisplayName("Anti-SSRF Policy: Prohibit private IPs, loopback, cloud metadata and internal domains")
    void shouldBlockAllSSRFVectors(String blockedTarget) {
        assertThrows(SSRFSecurityException.class, () -> {
            validationService.normalizeAndValidate(blockedTarget);
        }, "Target must trigger SSRFSecurityException: " + blockedTarget);
    }

    @Test
    @DisplayName("Formula Injection Hardening: Escape dangerous spreadsheet characters (=, +, -, @)")
    void shouldSanitizeSpreadsheetFormulaInjection() throws Exception {
        Method sanitizeMethod = ExcelReportService.class.getDeclaredMethod("sanitize", String.class);
        sanitizeMethod.setAccessible(true);

        assertEquals("'=cmd|'/C calc'!A0", sanitizeMethod.invoke(excelReportService, "=cmd|'/C calc'!A0"));
        assertEquals("'+1+1", sanitizeMethod.invoke(excelReportService, "+1+1"));
        assertEquals("'-2+5", sanitizeMethod.invoke(excelReportService, "-2+5"));
        assertEquals("'@SUM(A1:A5)", sanitizeMethod.invoke(excelReportService, "@SUM(A1:A5)"));
        assertEquals("google.com", sanitizeMethod.invoke(excelReportService, "google.com"));
        assertEquals("", sanitizeMethod.invoke(excelReportService, (Object) null));
    }

    @Test
    @DisplayName("Severity Floor Rule: Overall Risk Posture must elevate to at least HIGH if any HIGH finding exists")
    void shouldElevateOverallRiskLevelToSeverityFloor() {
        SecurityFinding highFinding = new SecurityFinding(1L, 1L, "HOST_MISMATCH", "Hostname Mismatch", "Cert mismatch", "HIGH", 30, "evidence", "remediation");
        
        // Even with a low score like 25, having a HIGH finding must elevate overall risk to HIGH
        String level = riskScoringService.determineRiskLevel(25, List.of(highFinding));
        assertEquals("HIGH", level, "Finding of severity HIGH must elevate posture to HIGH");

        SecurityFinding critFinding = new SecurityFinding(1L, 1L, "EXP_EXPIRED", "Expired Cert", "Cert expired", "CRITICAL", 40, "evidence", "remediation");
        String critLevel = riskScoringService.determineRiskLevel(40, List.of(highFinding, critFinding));
        assertEquals("CRITICAL", critLevel, "Finding of severity CRITICAL must elevate posture to CRITICAL");
    }
}
