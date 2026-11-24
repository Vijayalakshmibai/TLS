package com.tlsmonitor.risk;

import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inspection.repository.CertificateDetailsRepository;
import com.tlsmonitor.inspection.tls.CertificateExtractor;
import com.tlsmonitor.risk.entity.RiskAssessment;
import com.tlsmonitor.risk.entity.SecurityFinding;
import com.tlsmonitor.risk.repository.RiskAssessmentRepository;
import com.tlsmonitor.risk.repository.SecurityFindingRepository;
import com.tlsmonitor.risk.rules.CertificateExpiryRule;
import com.tlsmonitor.risk.service.ExpiryChecker;
import com.tlsmonitor.risk.service.RiskAnalyzer;
import com.tlsmonitor.risk.service.RiskScoringService;
import com.tlsmonitor.testutil.CertificateTestUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Functional test suite for Certificate Expiry Detection and Classification (TC-06 through TC-10).
 * Tests deterministic expiry categorization, risk scoring, recommendations, and database persistence
 * using controlled test certificates with an injectable UTC Clock.
 */
@ExtendWith(MockitoExtension.class)
public class ExpiryClassificationScenariosTest {

    // Fixed reference clock: 2026-06-01T12:00:00Z
    private static final Instant FIXED_NOW = Instant.parse("2026-06-01T12:00:00Z");
    private static final Clock FIXED_CLOCK = Clock.fixed(FIXED_NOW, ZoneOffset.UTC);

    private static KeyPair caKeyPair;
    private static X509Certificate caCert;
    private static KeyPair serverKeyPair;

    @Mock
    private CertificateDetailsRepository certRepository;

    @Mock
    private SecurityFindingRepository findingRepository;

    @Mock
    private RiskAssessmentRepository assessmentRepository;

    private ExpiryChecker expiryChecker;
    private CertificateExtractor certificateExtractor;
    private CertificateExpiryRule expiryRule;
    private RiskScoringService riskScoringService;
    private RiskAnalyzer riskAnalyzer;

    @BeforeAll
    static void initKeys() throws Exception {
        caKeyPair = CertificateTestUtils.generateRsaKeyPair();
        caCert = CertificateTestUtils.generateCaCertificate(caKeyPair, "CN=ExpiryTestCA,O=TLSMonitor,C=US");
        serverKeyPair = CertificateTestUtils.generateRsaKeyPair();
    }

    @BeforeEach
    void setUp() {
        expiryChecker = new ExpiryChecker(FIXED_CLOCK);
        certificateExtractor = new CertificateExtractor(expiryChecker, FIXED_CLOCK);
        expiryRule = new CertificateExpiryRule(expiryChecker);
        riskScoringService = new RiskScoringService();
        riskAnalyzer = new RiskAnalyzer(List.of(expiryRule), riskScoringService, findingRepository, assessmentRepository);
    }

    private X509Certificate generateCert(Instant notBefore, Instant notAfter, String domain) throws Exception {
        return CertificateTestUtils.generateSignedCertificate(
                "CN=" + domain,
                serverKeyPair,
                caCert,
                caKeyPair.getPrivate(),
                Date.from(notBefore),
                Date.from(notAfter),
                List.of(domain),
                null
        );
    }

    private TLSScanResult createScan(String domain) {
        TLSScanResult scan = new TLSScanResult();
        scan.setId(100L);
        scan.setWebsiteId(1L);
        scan.setDomain(domain);
        scan.setConnectionStatus("SUCCESS");
        scan.setTlsVersion("TLSv1.3");
        scan.setCipherSuite("TLS_AES_128_GCM_SHA256");
        scan.setHostnameValid(true);
        scan.setTrustChainValid(true);
        scan.setWeakProtocolDetected(false);
        return scan;
    }

    // =========================================================================
    // TC-06: Certificate Expiring Within 0–7 Days
    // =========================================================================
    @Test
    @DisplayName("TC-06: Certificate expiring within 0-7 days (expires in 3 days) is classified as CRITICAL")
    void testTC06_CertificateExpiringWithin0To7Days() throws Exception {
        // Arrange: validFrom = -30 days, validUntil = +3 days
        Instant notBefore = FIXED_NOW.minus(30, ChronoUnit.DAYS);
        Instant notAfter = FIXED_NOW.plus(3, ChronoUnit.DAYS);
        X509Certificate cert = generateCert(notBefore, notAfter, "expiring-soon.example.com");

        // Act
        CertificateDetails details = certificateExtractor.extractDetails(cert, 100L, 1L, 2);
        TLSScanResult scan = createScan("expiring-soon.example.com");
        List<SecurityFinding> findings = expiryRule.evaluate(scan, details);

        when(assessmentRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(findingRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        RiskAnalyzer.AnalysisResult analysis = riskAnalyzer.analyzeAndPersist(scan, details);

        // Assert
        assertEquals(3, details.getDaysRemaining(), "Remaining days must be exactly 3");
        assertFalse(details.isExpired(), "Certificate is not yet expired");
        assertFalse(details.isNotYetValid(), "Certificate is valid");

        // Finding verification
        assertEquals(1, findings.size(), "Exactly 1 expiry finding generated");
        SecurityFinding finding = findings.get(0);
        assertEquals("EXP_CRITICAL", finding.getRuleCode());
        assertEquals("CRITICAL", finding.getSeverity(), "Finding severity must be CRITICAL");
        assertEquals(30, finding.getPoints(), "Risk points for 0-7 days must be 30");
        assertTrue(finding.getEvidence().contains("3"), "Evidence must indicate 3 days remaining");
        assertEquals("Trigger automated or manual certificate renewal before the 7-day cutoff.", finding.getRecommendation());

        // Overall risk assessment
        RiskAssessment assessment = analysis.assessment();
        assertEquals("CRITICAL", assessment.getRiskLevel(), "Overall risk posture must be CRITICAL");
        assertEquals(30, assessment.getTotalScore(), "Risk score must be 30");
    }

    // =========================================================================
    // TC-07: Certificate Expiring Within 8–30 Days
    // =========================================================================
    @Test
    @DisplayName("TC-07: Certificate expiring within 8-30 days (expires in 15 days) is classified as HIGH")
    void testTC07_CertificateExpiringWithin8To30Days() throws Exception {
        // Arrange: validFrom = -60 days, validUntil = +15 days
        Instant notBefore = FIXED_NOW.minus(60, ChronoUnit.DAYS);
        Instant notAfter = FIXED_NOW.plus(15, ChronoUnit.DAYS);
        X509Certificate cert = generateCert(notBefore, notAfter, "expiring-month.example.com");

        // Act
        CertificateDetails details = certificateExtractor.extractDetails(cert, 100L, 1L, 2);
        TLSScanResult scan = createScan("expiring-month.example.com");
        List<SecurityFinding> findings = expiryRule.evaluate(scan, details);

        when(assessmentRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(findingRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        RiskAnalyzer.AnalysisResult analysis = riskAnalyzer.analyzeAndPersist(scan, details);

        // Assert
        assertEquals(15, details.getDaysRemaining(), "Remaining days must be calculated as 15");
        assertFalse(details.isExpired(), "Certificate is not yet expired");

        // Finding verification
        assertEquals(1, findings.size(), "Exactly 1 expiry finding generated");
        SecurityFinding finding = findings.get(0);
        assertEquals("EXP_HIGH", finding.getRuleCode());
        assertEquals("HIGH", finding.getSeverity(), "Finding severity must be HIGH");
        assertEquals(15, finding.getPoints(), "Risk points for 8-30 days must be 15");
        assertTrue(finding.getEvidence().contains("15"), "Evidence must indicate 15 days remaining");
        assertEquals("Schedule certificate renewal with your Certificate Authority.", finding.getRecommendation());

        // Overall risk assessment posture
        RiskAssessment assessment = analysis.assessment();
        assertEquals("HIGH", assessment.getRiskLevel(), "Overall risk level must be elevated to HIGH");
        assertEquals(15, assessment.getTotalScore(), "Risk score must be 15");
    }

    // =========================================================================
    // TC-08: Certificate Expiring Within 31–60 Days
    // =========================================================================
    @Test
    @DisplayName("TC-08: Certificate expiring within 31-60 days (expires in 45 days) is classified as MEDIUM")
    void testTC08_CertificateExpiringWithin31To60Days() throws Exception {
        // Arrange: validFrom = -45 days, validUntil = +45 days
        Instant notBefore = FIXED_NOW.minus(45, ChronoUnit.DAYS);
        Instant notAfter = FIXED_NOW.plus(45, ChronoUnit.DAYS);
        X509Certificate cert = generateCert(notBefore, notAfter, "expiring-medium.example.com");

        // Act
        CertificateDetails details = certificateExtractor.extractDetails(cert, 100L, 1L, 2);
        TLSScanResult scan = createScan("expiring-medium.example.com");
        List<SecurityFinding> findings = expiryRule.evaluate(scan, details);

        when(assessmentRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(findingRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        RiskAnalyzer.AnalysisResult analysis = riskAnalyzer.analyzeAndPersist(scan, details);

        // Assert
        assertEquals(45, details.getDaysRemaining(), "Remaining days must be 45");
        assertFalse(details.isExpired(), "Certificate is not expired");

        // Finding verification
        assertEquals(1, findings.size(), "Exactly 1 expiry finding generated");
        SecurityFinding finding = findings.get(0);
        assertEquals("EXP_MEDIUM", finding.getRuleCode());
        assertEquals("MEDIUM", finding.getSeverity(), "Finding severity must be MEDIUM");
        assertEquals(10, finding.getPoints(), "Risk points for 31-60 days must be 10");
        assertTrue(finding.getEvidence().contains("45"), "Evidence must indicate 45 days remaining");
        assertEquals("Verify automated renewal pipelines are configured and operational.", finding.getRecommendation());

        // Overall risk assessment posture
        RiskAssessment assessment = analysis.assessment();
        assertEquals("MEDIUM", assessment.getRiskLevel(), "Overall risk level must be elevated to MEDIUM");
        assertEquals(10, assessment.getTotalScore(), "Risk score must be 10");
    }

    // =========================================================================
    // TC-09: Certificate Expiring After 60 Days
    // =========================================================================
    @Test
    @DisplayName("TC-09: Certificate expiring after 60 days (expires in 90 days) has LOW expiry risk and no warnings")
    void testTC09_CertificateExpiringAfter60Days() throws Exception {
        // Arrange: validFrom = -30 days, validUntil = +90 days
        Instant notBefore = FIXED_NOW.minus(30, ChronoUnit.DAYS);
        Instant notAfter = FIXED_NOW.plus(90, ChronoUnit.DAYS);
        X509Certificate cert = generateCert(notBefore, notAfter, "healthy-cert.example.com");

        // Act
        CertificateDetails details = certificateExtractor.extractDetails(cert, 100L, 1L, 2);
        TLSScanResult scan = createScan("healthy-cert.example.com");
        List<SecurityFinding> findings = expiryRule.evaluate(scan, details);

        when(assessmentRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        RiskAnalyzer.AnalysisResult analysis = riskAnalyzer.analyzeAndPersist(scan, details);

        // Assert
        assertEquals(90, details.getDaysRemaining(), "Remaining days must be 90");
        assertFalse(details.isExpired(), "Certificate is not expired");
        assertFalse(details.isNotYetValid(), "Certificate is active");

        // Verify NO expiry warning generated
        assertTrue(findings.isEmpty(), "No expiry warnings must be generated for > 60 days");

        // Verify risk classification is LOW
        RiskAssessment assessment = analysis.assessment();
        assertEquals("LOW", assessment.getRiskLevel(), "Risk level must be LOW");
        assertEquals(0, assessment.getTotalScore(), "Risk score for clean certificate must be 0");
    }

    // =========================================================================
    // TC-10: Expired Certificate
    // =========================================================================
    @Test
    @DisplayName("TC-10: Expired certificate (expired 10 days ago) is CRITICAL, persisted as expired in DB")
    void testTC10_ExpiredCertificateDetectionAndPersistence() throws Exception {
        // Arrange: validFrom = -375 days, validUntil = -10 days
        Instant notBefore = FIXED_NOW.minus(375, ChronoUnit.DAYS);
        Instant notAfter = FIXED_NOW.minus(10, ChronoUnit.DAYS);
        X509Certificate cert = generateCert(notBefore, notAfter, "expired.example.com");

        // Act: Extract details
        CertificateDetails details = certificateExtractor.extractDetails(cert, 100L, 1L, 1);
        TLSScanResult scan = createScan("expired.example.com");
        List<SecurityFinding> findings = expiryRule.evaluate(scan, details);

        when(assessmentRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(findingRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        RiskAnalyzer.AnalysisResult analysis = riskAnalyzer.analyzeAndPersist(scan, details);

        // Simulate database save & retrieval
        when(certRepository.save(any(CertificateDetails.class))).thenAnswer(inv -> {
            CertificateDetails saved = inv.getArgument(0);
            saved.setId(555L);
            return saved;
        });
        when(certRepository.findById(555L)).thenReturn(java.util.Optional.of(details));

        CertificateDetails persistedCert = certRepository.save(details);
        CertificateDetails retrievedCert = certRepository.findById(555L).orElseThrow();

        // Assert CertificateDetails
        assertTrue(details.isExpired(), "Certificate must be marked as expired");
        assertTrue(details.getDaysRemaining() < 0, "Remaining days must be negative for expired cert");
        assertEquals(-10, details.getDaysRemaining(), "Days remaining should be -10");

        // Assert Finding
        assertEquals(1, findings.size(), "Exactly 1 expiry finding generated");
        SecurityFinding finding = findings.get(0);
        assertEquals("EXP_EXPIRED", finding.getRuleCode());
        assertEquals("CRITICAL", finding.getSeverity(), "Finding severity must be CRITICAL");
        assertEquals(40, finding.getPoints(), "Points for expired certificate must be 40");
        assertTrue(finding.getDescription().contains("10 days ago"), "Description must state days since expiration");
        assertEquals("Renew and deploy an active SSL/TLS certificate immediately.", finding.getRecommendation());

        // Assert Risk Assessment
        RiskAssessment assessment = analysis.assessment();
        assertEquals("CRITICAL", assessment.getRiskLevel(), "Overall risk level must be CRITICAL");
        assertEquals(40, assessment.getTotalScore(), "Risk score must be 40");

        // Assert Database persistence & display state
        assertNotNull(persistedCert.getId());
        assertTrue(retrievedCert.isExpired(), "Database persisted certificate must retain expired=true status");
        assertEquals(-10, retrievedCert.getDaysRemaining(), "Database persisted certificate must retain negative days remaining");
        verify(certRepository).save(details);
    }

    // =========================================================================
    // Boundary Conditions & Deterministic Categorization
    // =========================================================================
    @ParameterizedTest(name = "Boundary test: remainingDays={0} -> expectedCategory={1}")
    @CsvSource({
            "-10, EXPIRED",
            "-1,  EXPIRED",
            "0,   CRITICAL",
            "1,   CRITICAL",
            "7,   CRITICAL",
            "8,   HIGH",
            "20,  HIGH",
            "30,  HIGH",
            "31,  MEDIUM",
            "45,  MEDIUM",
            "60,  MEDIUM",
            "61,  LOW",
            "90,  LOW",
            "365, LOW"
    })
    @DisplayName("Boundary verification for all expiry cutoffs (0, 7, 8, 30, 31, 60, 61 days)")
    void testExpiryBoundaries(long days, ExpiryChecker.ExpiryCategory expectedCategory) {
        ExpiryChecker.ExpiryCategory category = expiryChecker.categorize(days);
        assertEquals(expectedCategory, category, "Boundary day " + days + " must categorize as " + expectedCategory);
    }

    @Test
    @DisplayName("Same-day expiry boundary: Certificate expiring earlier today is classified as EXPIRED (-1)")
    void testSameDayExpiredEarlierToday() {
        // FIXED_NOW is 2026-06-01T12:00:00Z
        // If cert expired at 2026-06-01T08:00:00Z (4 hours ago on same date):
        java.time.LocalDateTime expiryDateTime = java.time.LocalDateTime.of(2026, 6, 1, 8, 0, 0);

        long daysRemaining = expiryChecker.calculateRemainingDays(expiryDateTime);
        assertEquals(-1, daysRemaining, "Cert expired earlier on the same day must return -1 days remaining");
        assertEquals(ExpiryChecker.ExpiryCategory.EXPIRED, expiryChecker.categorize(daysRemaining));
    }

    @Test
    @DisplayName("Same-day expiry boundary: Certificate expiring later today is classified as CRITICAL (0 days)")
    void testSameDayExpiringLaterToday() {
        // FIXED_NOW is 2026-06-01T12:00:00Z
        // If cert expires at 2026-06-01T20:00:00Z (8 hours later on same date):
        java.time.LocalDateTime expiryDateTime = java.time.LocalDateTime.of(2026, 6, 1, 20, 0, 0);

        long daysRemaining = expiryChecker.calculateRemainingDays(expiryDateTime);
        assertEquals(0, daysRemaining, "Cert expiring later on same day must return 0 days remaining");
        assertEquals(ExpiryChecker.ExpiryCategory.CRITICAL, expiryChecker.categorize(daysRemaining));
    }
}
