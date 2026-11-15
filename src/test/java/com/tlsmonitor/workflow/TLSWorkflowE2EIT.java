package com.tlsmonitor.workflow;

import com.tlsmonitor.alerts.entity.Alert;
import com.tlsmonitor.alerts.repository.AlertRepository;
import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inspection.repository.CertificateDetailsRepository;
import com.tlsmonitor.inspection.repository.TLSScanResultRepository;
import com.tlsmonitor.inspection.service.ScanOrchestratorService;
import com.tlsmonitor.inspection.tls.TLSInspector;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.inventory.repository.WebsiteRepository;
import com.tlsmonitor.inventory.service.WebsiteService;
import com.tlsmonitor.reporting.service.ExcelReportService;
import com.tlsmonitor.reporting.service.PdfReportService;
import com.tlsmonitor.risk.entity.RiskAssessment;
import com.tlsmonitor.risk.entity.SecurityFinding;
import com.tlsmonitor.risk.repository.RiskAssessmentRepository;
import com.tlsmonitor.risk.repository.SecurityFindingRepository;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.ss.usermodel.WorkbookFactory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.io.ByteArrayInputStream;
import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

@SpringBootTest
@DisplayName("End-to-End TLS Workflow Integration Test")
class TLSWorkflowE2EIT {

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
    private PdfReportService pdfReportService;

    @Autowired
    private ExcelReportService excelReportService;

    @MockitoBean
    private TLSInspector tlsInspector;

    @MockitoBean
    private com.tlsmonitor.inventory.service.WebsiteValidationService validationService;

    @Test
    @DisplayName("Complete E2E Workflow: Add Website -> Orchestrated Scan -> Risk Scoring -> Alerts -> PDF & Excel Generation")
    void testCompleteTlsMonitoringWorkflow() throws Exception {
        when(validationService.normalizeAndValidate(anyString()))
                .thenReturn(new com.tlsmonitor.inventory.service.WebsiteValidationService.NormalizedTarget("example.com", 443, "https://example.com"));

        // 1. Register a new website in inventory
        Website site = new Website("example.com", "https://example.com", "E2E Test Site");
        Website created = websiteService.addWebsite(site);
        assertNotNull(created.getId());
        assertEquals("ACTIVE", created.getStatus());

        // 2. Prepare mock TLS inspection outcome
        TLSScanResult mockScan = new TLSScanResult();
        mockScan.setWebsiteId(created.getId());
        mockScan.setDomain(created.getDomain());
        mockScan.setPort(443);
        mockScan.setConnectionStatus("SUCCESS");
        mockScan.setTlsVersion("TLSv1.3");
        mockScan.setCipherSuite("TLS_AES_128_GCM_SHA256");
        mockScan.setHostnameValid(true);
        mockScan.setTrustChainValid(true);
        mockScan.setSupportedProtocols("TLSv1.2, TLSv1.3");
        mockScan.setResponseTimeMs(42);
        mockScan.setResolvedIp("93.184.216.34");

        CertificateDetails mockCert = new CertificateDetails();
        mockCert.setWebsiteId(created.getId());
        mockCert.setSubject("CN=example.com");
        mockCert.setIssuer("CN=DigiCert Global Root CA");
        mockCert.setSerialNumber("ABC123E2E999");
        mockCert.setSignatureAlgorithm("SHA256withRSA");
        mockCert.setPublicKeyAlgorithm("RSA");
        mockCert.setKeySize(2048);
        mockCert.setDaysRemaining(18); // <= 30 days remaining, triggers expiry warning
        mockCert.setExpired(false);
        mockCert.setSelfSigned(false);
        mockCert.setValidFrom(LocalDateTime.now().minusDays(72));
        mockCert.setValidUntil(LocalDateTime.now().plusDays(18));
        mockCert.setSha256Fingerprint("11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF");

        when(tlsInspector.inspect(eq(created.getId()), eq(created.getDomain()), eq(443)))
                .thenReturn(new TLSInspector.InspectionOutcome(mockScan, mockCert));

        // 3. Trigger the unified scan orchestrator pipeline
        ScanOrchestratorService.ScanPipelineResult pipelineResult = scanOrchestratorService.executeScanPipeline(created.getId());
        assertNotNull(pipelineResult);

        // 4. Verify scan result was persisted in DB
        List<TLSScanResult> scans = scanResultRepository.findByWebsiteIdOrderByScannedAtDesc(created.getId());
        assertFalse(scans.isEmpty(), "Scan result should be stored in database");
        TLSScanResult storedScan = scans.get(0);
        assertEquals("TLSv1.3", storedScan.getTlsVersion());
        assertEquals("SUCCESS", storedScan.getConnectionStatus());

        // 5. Verify certificate details were persisted
        CertificateDetails storedCert = certificateDetailsRepository.findFirstByWebsiteIdOrderByIdDesc(created.getId()).orElse(null);
        assertNotNull(storedCert, "Certificate details should be stored");
        assertEquals("CN=example.com", storedCert.getSubject());
        assertEquals(18, storedCert.getDaysRemaining());

        // 6. Verify risk assessment was executed and persisted
        RiskAssessment storedRisk = riskAssessmentRepository.findFirstByWebsiteIdOrderByAssessedAtDesc(created.getId()).orElse(null);
        assertNotNull(storedRisk, "Risk assessment should be stored");
        assertTrue(storedRisk.getTotalScore() > 0, "Risk score should reflect the 18-day expiry threshold");

        // 7. Verify security findings were recorded
        List<SecurityFinding> findings = securityFindingRepository.findByScanId(storedScan.getId());
        assertFalse(findings.isEmpty(), "Security findings should be generated");

        // 8. Verify alert was generated for the 18-day expiry warning
        List<Alert> alerts = alertRepository.findByWebsiteIdOrderByCreatedAtDesc(created.getId());
        assertFalse(alerts.isEmpty(), "Alert should be created for certificate expiring in 18 days");
        assertTrue(alerts.stream().anyMatch(a -> "EXPIRY_WARNING_30D".equals(a.getAlertType())));

        // 9. Verify Website entity status and lastScannedAt timestamp were updated
        Website updatedWebsite = websiteRepository.findById(created.getId()).orElseThrow();
        assertNotNull(updatedWebsite.getLastScannedAt(), "lastScannedAt timestamp must be updated");

        // 10. Verify PDF Report Generation
        byte[] pdfReport = pdfReportService.generateWebsiteReport(updatedWebsite, storedScan, storedCert, storedRisk, findings);
        assertNotNull(pdfReport);
        assertTrue(pdfReport.length > 500);
        assertEquals('%', (char) pdfReport[0]);
        assertEquals('P', (char) pdfReport[1]);
        assertEquals('D', (char) pdfReport[2]);
        assertEquals('F', (char) pdfReport[3]);

        // 11. Verify Multi-Sheet Excel Report Generation
        byte[] excelReport = excelReportService.generateWorkbook(
                List.of(updatedWebsite),
                List.of(storedScan),
                List.of(storedCert),
                List.of(storedRisk),
                findings,
                alerts
        );
        assertNotNull(excelReport);
        try (Workbook wb = WorkbookFactory.create(new ByteArrayInputStream(excelReport))) {
            assertEquals(6, wb.getNumberOfSheets(), "Excel workbook must contain 6 sheets");
            assertEquals("Website Inventory", wb.getSheetAt(0).getSheetName());
            assertEquals("Certificate Details", wb.getSheetAt(1).getSheetName());
            assertEquals("TLS Inspections", wb.getSheetAt(2).getSheetName());
            assertEquals("Risk Assessments", wb.getSheetAt(3).getSheetName());
            assertEquals("Security Findings", wb.getSheetAt(4).getSheetName());
            assertEquals("Alert History", wb.getSheetAt(5).getSheetName());
        }
    }
}
