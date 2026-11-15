package com.tlsmonitor.risk;

import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.risk.entity.SecurityFinding;
import com.tlsmonitor.risk.repository.RiskAssessmentRepository;
import com.tlsmonitor.risk.repository.SecurityFindingRepository;
import com.tlsmonitor.risk.rules.*;
import com.tlsmonitor.risk.service.ExpiryChecker;
import com.tlsmonitor.risk.service.RiskAnalyzer;
import com.tlsmonitor.risk.service.RiskScoringService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RiskAnalyzerTest {

    @Mock
    private SecurityFindingRepository findingRepository;

    @Mock
    private RiskAssessmentRepository assessmentRepository;

    private RiskAnalyzer riskAnalyzer;
    private RiskScoringService scoringService;
    private ExpiryChecker expiryChecker;

    @BeforeEach
    void setUp() {
        expiryChecker = new ExpiryChecker();
        scoringService = new RiskScoringService();

        List<RiskRule> rules = List.of(
                new CertificateExpiryRule(expiryChecker),
                new HostnameMismatchRule(),
                new UntrustedChainRule(),
                new WeakProtocolRule(),
                new WeakCipherRule(),
                new CertificateStrengthRule()
        );

        riskAnalyzer = new RiskAnalyzer(rules, scoringService, findingRepository, assessmentRepository);
    }

    @Test
    void testScoreCalculationAndCappingAt100() {
        List<SecurityFinding> findings = List.of(
                new SecurityFinding(1L, 1L, "EXP_01", "Expired", "Desc", "CRITICAL", 40, "Ev", "Rec"),
                new SecurityFinding(1L, 1L, "TRUST_01", "Untrusted", "Desc", "CRITICAL", 35, "Ev", "Rec"),
                new SecurityFinding(1L, 1L, "HOST_01", "Mismatch", "Desc", "HIGH", 30, "Ev", "Rec"),
                new SecurityFinding(1L, 1L, "PROTO_01", "Weak Proto", "Desc", "HIGH", 25, "Ev", "Rec")
        );

        // Sum would be 40+35+30+25 = 130, must cap at 100
        int score = scoringService.calculateScore(findings);
        assertEquals(100, score);
        assertEquals("CRITICAL", scoringService.determineRiskLevel(score));
    }

    @Test
    void testRiskLevelThresholds() {
        assertEquals("LOW", scoringService.determineRiskLevel(0));
        assertEquals("LOW", scoringService.determineRiskLevel(19));
        assertEquals("MEDIUM", scoringService.determineRiskLevel(20));
        assertEquals("MEDIUM", scoringService.determineRiskLevel(39));
        assertEquals("HIGH", scoringService.determineRiskLevel(40));
        assertEquals("HIGH", scoringService.determineRiskLevel(69));
        assertEquals("CRITICAL", scoringService.determineRiskLevel(70));
        assertEquals("CRITICAL", scoringService.determineRiskLevel(100));
    }

    @Test
    void testAnalyzeAndPersistWithMultipleVulnerabilities() {
        when(assessmentRepository.save(any())).thenAnswer(i -> i.getArgument(0));
        when(findingRepository.save(any())).thenAnswer(i -> i.getArgument(0));

        TLSScanResult scan = new TLSScanResult();
        scan.setId(10L);
        scan.setWebsiteId(1L);
        scan.setDomain("badssl.example.com");
        scan.setConnectionStatus("SUCCESS");
        scan.setTlsVersion("TLSv1.2");
        scan.setCipherSuite("TLS_RSA_WITH_3DES_EDE_CBC_SHA");
        scan.setHostnameValid(false); // 30 pts
        scan.setTrustChainValid(false); // 35 pts
        scan.setWeakProtocolDetected(true); // 25 pts

        CertificateDetails cert = new CertificateDetails();
        cert.setValidUntil(LocalDateTime.now(ZoneOffset.UTC).minusDays(5)); // Expired: 40 pts
        cert.setSignatureAlgorithm("MD5withRSA"); // 20 pts
        cert.setPublicKeyAlgorithm("RSA");
        cert.setKeySize(1024); // 20 pts

        RiskAnalyzer.AnalysisResult result = riskAnalyzer.analyzeAndPersist(scan, cert);

        assertNotNull(result);
        assertNotNull(result.assessment());
        assertEquals(100, result.assessment().getTotalScore(), "Total score capped at 100");
        assertEquals("CRITICAL", result.assessment().getRiskLevel());
        assertTrue(result.findings().size() >= 5);

        verify(assessmentRepository).save(any());
        verify(findingRepository, atLeast(5)).save(any());
    }

    @Test
    void testCleanWebsiteReceivesLowRiskScore() {
        when(assessmentRepository.save(any())).thenAnswer(i -> i.getArgument(0));

        TLSScanResult scan = new TLSScanResult();
        scan.setId(20L);
        scan.setWebsiteId(2L);
        scan.setDomain("google.com");
        scan.setConnectionStatus("SUCCESS");
        scan.setTlsVersion("TLSv1.3");
        scan.setCipherSuite("TLS_AES_128_GCM_SHA256");
        scan.setHostnameValid(true);
        scan.setTrustChainValid(true);
        scan.setWeakProtocolDetected(false);

        CertificateDetails cert = new CertificateDetails();
        cert.setValidUntil(LocalDateTime.now(ZoneOffset.UTC).plusDays(85)); // > 60 days: 0 pts
        cert.setSignatureAlgorithm("SHA256withRSA");
        cert.setPublicKeyAlgorithm("RSA");
        cert.setKeySize(2048);

        RiskAnalyzer.AnalysisResult result = riskAnalyzer.analyzeAndPersist(scan, cert);

        assertNotNull(result);
        assertEquals(0, result.assessment().getTotalScore());
        assertEquals("LOW", result.assessment().getRiskLevel());
        assertEquals(0, result.findings().size());
    }
}
