package com.tlsmonitor.workflow;

import com.tlsmonitor.alerts.entity.Alert;
import com.tlsmonitor.alerts.repository.AlertRepository;
import com.tlsmonitor.alerts.service.AlertService;
import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inspection.repository.CertificateDetailsRepository;
import com.tlsmonitor.inspection.repository.TLSScanResultRepository;
import com.tlsmonitor.inspection.service.ScanOrchestratorService;
import com.tlsmonitor.inspection.tls.TLSInspector;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.inventory.repository.WebsiteRepository;
import com.tlsmonitor.inventory.service.WebsiteService;
import com.tlsmonitor.risk.entity.RiskAssessment;
import com.tlsmonitor.risk.entity.SecurityFinding;
import com.tlsmonitor.risk.repository.RiskAssessmentRepository;
import com.tlsmonitor.risk.repository.SecurityFindingRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/**
 * Integration tests for TC-21 to TC-25:
 * - TC-21: Website Registration to TLS Scan
 * - TC-22: Scan Results to Risk Assessment
 * - TC-23: Risk Assessment to Alert Generation
 * - TC-24: Database Persistence and Relationships
 * - TC-25: Alert Deduplication and Resolution
 */
@SpringBootTest
@ActiveProfiles("test")
@DisplayName("System Integration & Module Cross-Verification (TC-21 to TC-25)")
public class SystemIntegrationScenariosTest {

    @Autowired
    private WebsiteService websiteService;

    @Autowired
    private WebsiteRepository websiteRepository;

    @Autowired
    private ScanOrchestratorService scanOrchestratorService;

    @Autowired
    private TLSScanResultRepository scanResultRepository;

    @Autowired
    private CertificateDetailsRepository certificateDetailsRepository;

    @Autowired
    private RiskAssessmentRepository riskAssessmentRepository;

    @Autowired
    private SecurityFindingRepository securityFindingRepository;

    @Autowired
    private AlertRepository alertRepository;

    @Autowired
    private AlertService alertService;

    @MockitoBean
    private TLSInspector tlsInspector;

    @BeforeEach
    void cleanDatabase() {
        alertRepository.deleteAll();
        securityFindingRepository.deleteAll();
        riskAssessmentRepository.deleteAll();
        certificateDetailsRepository.deleteAll();
        scanResultRepository.deleteAll();
        websiteRepository.deleteAll();
    }

    private Website registerTestWebsite(String domain) {
        Website site = new Website(domain, "https://" + domain, "Integration Test Target");
        site.setStatus("ACTIVE");
        site.setContactEmail("ops@" + domain);
        site.setCreatedAt(LocalDateTime.now());
        site.setUpdatedAt(LocalDateTime.now());
        return websiteRepository.save(site);
    }

    private TLSScanResult createSampleScan(Long websiteId, String domain, boolean hostnameValid, boolean trustValid) {
        TLSScanResult scan = new TLSScanResult();
        scan.setWebsiteId(websiteId);
        scan.setDomain(domain);
        scan.setPort(443);
        scan.setConnectionStatus("SUCCESS");
        scan.setTlsVersion("TLSv1.3");
        scan.setCipherSuite("TLS_AES_256_GCM_SHA384");
        scan.setHostnameValid(hostnameValid);
        scan.setTrustChainValid(trustValid);
        scan.setSupportedProtocols("TLSv1.2, TLSv1.3");
        scan.setWeakProtocolDetected(false);
        scan.setResponseTimeMs(45);
        scan.setResolvedIp("93.184.216.34");
        scan.setScannedAt(LocalDateTime.now());
        return scan;
    }

    private CertificateDetails createSampleCertificate(Long websiteId, int daysRemaining, boolean expired, boolean selfSigned) {
        CertificateDetails cert = new CertificateDetails();
        cert.setWebsiteId(websiteId);
        cert.setSubject("CN=example.com,O=IntegrationCorp,C=US");
        cert.setIssuer("CN=TrustedRootCA,O=TrustCorp,C=US");
        cert.setSerialNumber("SN-INT-999-ABCD");
        cert.setSignatureAlgorithm("SHA256withRSA");
        cert.setPublicKeyAlgorithm("RSA");
        cert.setKeySize(2048);
        cert.setDaysRemaining(daysRemaining);
        cert.setExpired(expired);
        cert.setSelfSigned(selfSigned);
        cert.setValidFrom(LocalDateTime.now().minusDays(60));
        cert.setValidUntil(LocalDateTime.now().plusDays(daysRemaining));
        cert.setSha256Fingerprint("AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99");
        return cert;
    }

    // =========================================================================
    // TC-21: Website Registration to TLS Scan
    // =========================================================================
    @Test
    @DisplayName("TC-21: Website Registration to TLS Scan - Module 1 to Module 2 integration")
    void testTC21_WebsiteRegistrationToTlsScan() {
        // Step 1: Register website through Module 1
        Website site = registerTestWebsite("tc21.example.com");
        assertNotNull(site.getId(), "Website must be persisted with generated ID");

        // Step 2: Configure Module 2 TLS inspection outcome
        TLSScanResult mockScan = createSampleScan(site.getId(), site.getDomain(), true, true);
        CertificateDetails mockCert = createSampleCertificate(site.getId(), 120, false, false);
        when(tlsInspector.inspect(eq(site.getId()), eq(site.getDomain()), eq(443)))
                .thenReturn(new TLSInspector.InspectionOutcome(mockScan, mockCert));

        // Step 3: Trigger scan through orchestrator
        ScanOrchestratorService.ScanPipelineResult pipelineResult = scanOrchestratorService.executeScanPipeline(site.getId());

        // Step 4: Verify Module 2 inspected and linked results
        assertNotNull(pipelineResult);
        assertNotNull(pipelineResult.scanResult());
        assertEquals(site.getId(), pipelineResult.scanResult().getWebsiteId(), "ScanResult must link to the correct websiteId");
        assertEquals("tc21.example.com", pipelineResult.scanResult().getDomain());
        assertEquals("SUCCESS", pipelineResult.scanResult().getConnectionStatus());

        // Step 5: Verify scan is retrievable from repository
        List<TLSScanResult> history = scanResultRepository.findByWebsiteIdOrderByScannedAtDesc(site.getId());
        assertEquals(1, history.size(), "Scan history should contain exactly 1 scan");
        assertEquals(pipelineResult.scanResult().getId(), history.get(0).getId());
    }

    // =========================================================================
    // TC-22: Scan Results to Risk Assessment
    // =========================================================================
    @Test
    @DisplayName("TC-22: Scan Results to Risk Assessment - Module 2 to Module 3 evaluation")
    void testTC22_ScanResultsToRiskAssessment() {
        // Step 1: Register target
        Website site = registerTestWebsite("tc22.example.com");

        // Step 2: Create scan with multiple security issues (expired cert, hostname mismatch, untrusted chain)
        TLSScanResult scan = createSampleScan(site.getId(), site.getDomain(), false, false);
        scan.setTlsVersion("TLSv1.0"); // Weak protocol
        scan.setWeakProtocolDetected(true);
        scan.setSupportedProtocols("TLSv1.0, TLSv1.2");

        CertificateDetails cert = createSampleCertificate(site.getId(), -5, true, true);
        cert.setKeySize(1024); // Weak key size
        cert.setSignatureAlgorithm("MD5withRSA"); // Weak signature algorithm

        when(tlsInspector.inspect(eq(site.getId()), eq(site.getDomain()), eq(443)))
                .thenReturn(new TLSInspector.InspectionOutcome(scan, cert));

        // Step 3: Run scan pipeline
        ScanOrchestratorService.ScanPipelineResult result = scanOrchestratorService.executeScanPipeline(site.getId());

        // Step 4: Verify Module 3 evaluated findings and calculated risk score
        RiskAssessment risk = result.riskAssessment();
        assertNotNull(risk, "Risk assessment must be produced");
        assertEquals(site.getId(), risk.getWebsiteId());
        assertEquals(result.scanResult().getId(), risk.getScanId());

        // With expired cert, weak protocol, weak key, weak signature, score must be severe
        assertEquals("CRITICAL", risk.getRiskLevel(), "Multiple severe issues must classify as CRITICAL");
        assertTrue(risk.getTotalScore() >= 50, "Risk score must be significantly elevated");

        // Step 5: Verify security findings generated and linked
        List<SecurityFinding> findings = result.findings();
        assertFalse(findings.isEmpty(), "Security findings must be generated");
        assertTrue(findings.stream().anyMatch(f -> "EXP_EXPIRED".equals(f.getRuleCode())), "Expired certificate finding expected");
        assertTrue(findings.stream().anyMatch(f -> "HOST_MISMATCH".equals(f.getRuleCode())), "Hostname mismatch finding expected");
        assertTrue(findings.stream().anyMatch(f -> f.getRuleCode().startsWith("TRUST_")), "Untrusted chain finding expected");
        assertTrue(findings.stream().anyMatch(f -> "PROTO_WEAK_VERSION".equals(f.getRuleCode())), "Weak protocol finding expected");

        // Verify all findings link to the scan and website
        for (SecurityFinding finding : findings) {
            assertEquals(result.scanResult().getId(), finding.getScanId());
            assertEquals(site.getId(), finding.getWebsiteId());
        }
    }

    // =========================================================================
    // TC-23: Risk Assessment to Alert Generation
    // =========================================================================
    @Test
    @DisplayName("TC-23: Risk Assessment to Alert Generation - Module 3 to Module 4 notification")
    void testTC23_RiskAssessmentToAlertGeneration() {
        // Step 1: Register target
        Website site = registerTestWebsite("tc23-alert.example.com");

        // Step 2: Inspection outcome with certificate expiring in 5 days (triggers EXPIRY_WARNING_7D)
        TLSScanResult scan = createSampleScan(site.getId(), site.getDomain(), true, true);
        CertificateDetails cert = createSampleCertificate(site.getId(), 5, false, false);

        when(tlsInspector.inspect(eq(site.getId()), eq(site.getDomain()), eq(443)))
                .thenReturn(new TLSInspector.InspectionOutcome(scan, cert));

        // Step 3: Execute scan pipeline
        ScanOrchestratorService.ScanPipelineResult result = scanOrchestratorService.executeScanPipeline(site.getId());

        // Step 4: Verify Module 4 created corresponding alerts
        List<Alert> alerts = alertRepository.findByWebsiteIdOrderByCreatedAtDesc(site.getId());
        assertFalse(alerts.isEmpty(), "Alerts must be created for 5-day expiry warning");

        Alert expiryAlert = alerts.stream()
                .filter(a -> "EXPIRY_WARNING_7D".equals(a.getAlertType()))
                .findFirst()
                .orElse(null);

        assertNotNull(expiryAlert, "EXPIRY_WARNING_7D alert must be present");
        assertEquals(site.getId(), expiryAlert.getWebsiteId());
        assertEquals("tc23-alert.example.com", expiryAlert.getDomain());
        assertEquals("CRITICAL", expiryAlert.getSeverity());
        assertTrue(expiryAlert.getMessage().contains("expires in 5 days"));
    }

    // =========================================================================
    // TC-24: Database Persistence and Relationships
    // =========================================================================
    @Test
    @DisplayName("TC-24: Database Persistence, Foreign Keys & Historical Scans Retained")
    void testTC24_DatabasePersistenceAndRelationships() {
        // Step 1: Register target
        Website site = registerTestWebsite("tc24-persistence.example.com");

        // Step 2: First scan (Scan 1)
        TLSScanResult scan1 = createSampleScan(site.getId(), site.getDomain(), true, true);
        CertificateDetails cert1 = createSampleCertificate(site.getId(), 15, false, false);
        when(tlsInspector.inspect(eq(site.getId()), eq(site.getDomain()), eq(443)))
                .thenReturn(new TLSInspector.InspectionOutcome(scan1, cert1));

        ScanOrchestratorService.ScanPipelineResult result1 = scanOrchestratorService.executeScanPipeline(site.getId());
        Long scan1Id = result1.scanResult().getId();

        // Step 3: Second scan (Scan 2) on the same website
        TLSScanResult scan2 = createSampleScan(site.getId(), site.getDomain(), true, true);
        scan2.setResponseTimeMs(88);
        CertificateDetails cert2 = createSampleCertificate(site.getId(), 14, false, false);
        when(tlsInspector.inspect(eq(site.getId()), eq(site.getDomain()), eq(443)))
                .thenReturn(new TLSInspector.InspectionOutcome(scan2, cert2));

        ScanOrchestratorService.ScanPipelineResult result2 = scanOrchestratorService.executeScanPipeline(site.getId());
        Long scan2Id = result2.scanResult().getId();

        // Step 4: Verify both historical scan records exist in database
        assertNotEquals(scan1Id, scan2Id, "Subsequent scans must produce distinct IDs");
        List<TLSScanResult> history = scanResultRepository.findByWebsiteIdOrderByScannedAtDesc(site.getId());
        assertEquals(2, history.size(), "Both historical scans must remain available in database");

        // Step 5: Verify entity relationships and linking
        CertificateDetails storedCert1 = certificateDetailsRepository.findByScanId(scan1Id).orElse(null);
        CertificateDetails storedCert2 = certificateDetailsRepository.findByScanId(scan2Id).orElse(null);
        assertNotNull(storedCert1);
        assertNotNull(storedCert2);
        assertEquals(scan1Id, storedCert1.getScanId());
        assertEquals(scan2Id, storedCert2.getScanId());
        assertEquals(site.getId(), storedCert1.getWebsiteId());
        assertEquals(site.getId(), storedCert2.getWebsiteId());

        // Verify risk assessments link to respective scans
        RiskAssessment risk1 = riskAssessmentRepository.findByScanId(scan1Id).orElse(null);
        RiskAssessment risk2 = riskAssessmentRepository.findByScanId(scan2Id).orElse(null);
        assertNotNull(risk1);
        assertNotNull(risk2);
        assertEquals(scan1Id, risk1.getScanId());
        assertEquals(scan2Id, risk2.getScanId());

        // Verify findings link to respective scans
        List<SecurityFinding> findings1 = securityFindingRepository.findByScanId(scan1Id);
        List<SecurityFinding> findings2 = securityFindingRepository.findByScanId(scan2Id);
        assertFalse(findings1.isEmpty());
        assertFalse(findings2.isEmpty());
        findings1.forEach(f -> assertEquals(scan1Id, f.getScanId()));
        findings2.forEach(f -> assertEquals(scan2Id, f.getScanId()));

        // Step 6: Verify website updated status and scan timestamp
        Website reloaded = websiteRepository.findById(site.getId()).orElse(null);
        assertNotNull(reloaded);
        assertNotNull(reloaded.getLastScannedAt());
    }

    // =========================================================================
    // TC-25: Alert Deduplication and Resolution
    // =========================================================================
    @Test
    @DisplayName("TC-25: Alert Deduplication on Repeated Scans & Automatic Transition to RESOLVED on Remediated Issue")
    void testTC25_AlertDeduplicationAndResolution() {
        // Step 1: Register target
        Website site = registerTestWebsite("tc25-dedup.example.com");

        // Step 2: First scan with expired certificate -> produces EXPIRED alert
        TLSScanResult scan1 = createSampleScan(site.getId(), site.getDomain(), true, true);
        CertificateDetails cert1 = createSampleCertificate(site.getId(), -3, true, false);
        when(tlsInspector.inspect(eq(site.getId()), eq(site.getDomain()), eq(443)))
                .thenReturn(new TLSInspector.InspectionOutcome(scan1, cert1));

        scanOrchestratorService.executeScanPipeline(site.getId());

        List<Alert> alertsAfterScan1 = alertRepository.findByWebsiteIdOrderByCreatedAtDesc(site.getId());
        long expiredAlertCount1 = alertsAfterScan1.stream().filter(a -> "EXPIRED".equals(a.getAlertType())).count();
        assertEquals(1, expiredAlertCount1, "Exactly 1 EXPIRED alert should be created on first scan");

        // Step 3: Repeated scan with STILL expired certificate -> duplicate alert must be suppressed
        TLSScanResult scan2 = createSampleScan(site.getId(), site.getDomain(), true, true);
        CertificateDetails cert2 = createSampleCertificate(site.getId(), -3, true, false);
        when(tlsInspector.inspect(eq(site.getId()), eq(site.getDomain()), eq(443)))
                .thenReturn(new TLSInspector.InspectionOutcome(scan2, cert2));

        scanOrchestratorService.executeScanPipeline(site.getId());

        List<Alert> alertsAfterScan2 = alertRepository.findByWebsiteIdOrderByCreatedAtDesc(site.getId());
        long expiredAlertCount2 = alertsAfterScan2.stream().filter(a -> "EXPIRED".equals(a.getAlertType())).count();
        assertEquals(1, expiredAlertCount2, "Repeated scan must suppress duplicate alert; count must remain 1");

        // Step 4: Remediate the issue! Certificate is renewed with 90 days validity. Scan again!
        TLSScanResult scan3 = createSampleScan(site.getId(), site.getDomain(), true, true);
        CertificateDetails cert3 = createSampleCertificate(site.getId(), 90, false, false);
        when(tlsInspector.inspect(eq(site.getId()), eq(site.getDomain()), eq(443)))
                .thenReturn(new TLSInspector.InspectionOutcome(scan3, cert3));

        scanOrchestratorService.executeScanPipeline(site.getId());

        // Step 5: Verify the EXPIRED alert has automatically transitioned to RESOLVED!
        List<Alert> alertsAfterScan3 = alertRepository.findByWebsiteIdOrderByCreatedAtDesc(site.getId());
        Alert resolvedAlert = alertsAfterScan3.stream()
                .filter(a -> "EXPIRED".equals(a.getAlertType()))
                .findFirst()
                .orElse(null);

        assertNotNull(resolvedAlert, "Alert record must still exist");
        assertEquals("RESOLVED", resolvedAlert.getStatus(), "Alert status must transition to RESOLVED when issue is fixed");
        assertNotNull(resolvedAlert.getResolvedAt(), "ResolvedAt timestamp must be populated upon resolution");
    }
}
