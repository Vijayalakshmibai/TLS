package com.tlsmonitor.inspection;

import com.tlsmonitor.alerts.entity.Alert;
import com.tlsmonitor.alerts.service.AlertService;
import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inspection.service.ScanOrchestratorService;
import com.tlsmonitor.inspection.service.TLSInspectionService;
import com.tlsmonitor.inspection.tls.TLSInspector;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.inventory.repository.WebsiteRepository;
import com.tlsmonitor.inventory.service.WebsiteService;
import com.tlsmonitor.risk.entity.RiskAssessment;
import com.tlsmonitor.risk.entity.SecurityFinding;
import com.tlsmonitor.risk.service.RiskAnalyzer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("ScanOrchestratorService Unit Tests")
class ScanOrchestratorServiceTest {

    @Mock
    private WebsiteService websiteService;

    @Mock
    private WebsiteRepository websiteRepository;

    @Mock
    private TLSInspectionService inspectionService;

    @Mock
    private RiskAnalyzer riskAnalyzer;

    @Mock
    private AlertService alertService;

    @InjectMocks
    private ScanOrchestratorService scanOrchestratorService;

    private Website website;
    private TLSScanResult scanResult;
    private CertificateDetails certDetails;

    @BeforeEach
    void setUp() {
        website = new Website("secure-host.example.com", "https://secure-host.example.com", "Orchestrator test host");
        website.setId(10L);
        website.setStatus("ACTIVE");

        scanResult = new TLSScanResult();
        scanResult.setWebsiteId(10L);
        scanResult.setDomain("secure-host.example.com");
        scanResult.setPort(443);
        scanResult.setConnectionStatus("SUCCESS");
        scanResult.setTlsVersion("TLSv1.3");
        scanResult.setCipherSuite("TLS_AES_256_GCM_SHA384");

        certDetails = new CertificateDetails();
        certDetails.setWebsiteId(10L);
        certDetails.setSubject("CN=secure-host.example.com");
        certDetails.setDaysRemaining(120);
    }

    @Test
    @DisplayName("Should execute end-to-end scan pipeline successfully for low risk site")
    void shouldExecutePipelineSuccessfully() {
        RiskAssessment lowRisk = new RiskAssessment(1L, 10L, 5, "LOW", 0);
        SecurityFinding finding = new SecurityFinding(1L, 10L, "INFO", "Nominal", "Clean", "LOW", 0, "Clean", "None");
        Alert alert = new Alert(10L, "secure-host.example.com", "INFO", "LOW", "Clean scan");

        when(websiteService.getWebsiteById(10L)).thenReturn(website);
        when(inspectionService.performScan(10L)).thenReturn(new TLSInspector.InspectionOutcome(scanResult, certDetails));
        when(riskAnalyzer.analyzeAndPersist(scanResult, certDetails)).thenReturn(new RiskAnalyzer.AnalysisResult(lowRisk, List.of(finding)));
        when(alertService.processScanAlerts(website, scanResult, certDetails, lowRisk)).thenReturn(List.of(alert));
        when(websiteRepository.save(any(Website.class))).thenAnswer(invocation -> invocation.getArgument(0));

        ScanOrchestratorService.ScanPipelineResult result = scanOrchestratorService.executeScanPipeline(10L);

        assertNotNull(result);
        assertEquals(website, result.website());
        assertEquals("ACTIVE", result.website().getStatus());
        assertNotNull(result.website().getLastScannedAt());
        assertEquals(5, result.riskAssessment().getTotalScore());
        assertEquals(1, result.findings().size());
        assertEquals(1, result.alerts().size());

        verify(websiteRepository).save(website);
    }

    @Test
    @DisplayName("Should update website status to CRITICAL when risk assessment is CRITICAL")
    void shouldUpdateStatusToCritical() {
        RiskAssessment criticalRisk = new RiskAssessment(1L, 10L, 85, "CRITICAL", 2);

        when(websiteService.getWebsiteById(10L)).thenReturn(website);
        when(inspectionService.performScan(10L)).thenReturn(new TLSInspector.InspectionOutcome(scanResult, certDetails));
        when(riskAnalyzer.analyzeAndPersist(scanResult, certDetails)).thenReturn(new RiskAnalyzer.AnalysisResult(criticalRisk, List.of()));
        when(alertService.processScanAlerts(website, scanResult, certDetails, criticalRisk)).thenReturn(List.of());
        when(websiteRepository.save(any(Website.class))).thenAnswer(invocation -> invocation.getArgument(0));

        ScanOrchestratorService.ScanPipelineResult result = scanOrchestratorService.executeScanPipeline(10L);

        assertEquals("CRITICAL", result.website().getStatus());
        verify(websiteRepository).save(website);
    }

    @Test
    @DisplayName("Should update website status to FAILED when TLS connection fails")
    void shouldUpdateStatusToFailedWhenUnreachable() {
        scanResult.setConnectionStatus("FAILED");
        RiskAssessment failedRisk = new RiskAssessment(1L, 10L, 50, "HIGH", 1);

        when(websiteService.getWebsiteById(10L)).thenReturn(website);
        when(inspectionService.performScan(10L)).thenReturn(new TLSInspector.InspectionOutcome(scanResult, null));
        when(riskAnalyzer.analyzeAndPersist(scanResult, null)).thenReturn(new RiskAnalyzer.AnalysisResult(failedRisk, List.of()));
        when(alertService.processScanAlerts(website, scanResult, null, failedRisk)).thenReturn(List.of());
        when(websiteRepository.save(any(Website.class))).thenAnswer(invocation -> invocation.getArgument(0));

        ScanOrchestratorService.ScanPipelineResult result = scanOrchestratorService.executeScanPipeline(10L);

        // Connection failed overrides or marks as FAILED or WARNING
        assertEquals("FAILED", result.website().getStatus());
        verify(websiteRepository).save(website);
    }
}
