package com.tlsmonitor.inspection.service;

import com.tlsmonitor.alerts.entity.Alert;
import com.tlsmonitor.alerts.service.AlertService;
import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inspection.tls.TLSInspector;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.inventory.repository.WebsiteRepository;
import com.tlsmonitor.inventory.service.WebsiteService;
import com.tlsmonitor.risk.entity.RiskAssessment;
import com.tlsmonitor.risk.entity.SecurityFinding;
import com.tlsmonitor.risk.service.RiskAnalyzer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class ScanOrchestratorService {

    private static final Logger log = LoggerFactory.getLogger(ScanOrchestratorService.class);

    private final WebsiteService websiteService;
    private final WebsiteRepository websiteRepository;
    private final TLSInspectionService inspectionService;
    private final RiskAnalyzer riskAnalyzer;
    private final AlertService alertService;

    public record ScanPipelineResult(
            Website website,
            TLSScanResult scanResult,
            CertificateDetails certificateDetails,
            RiskAssessment riskAssessment,
            List<SecurityFinding> findings,
            List<Alert> alerts
    ) {}

    public ScanOrchestratorService(WebsiteService websiteService,
                                   WebsiteRepository websiteRepository,
                                   TLSInspectionService inspectionService,
                                   RiskAnalyzer riskAnalyzer,
                                   AlertService alertService) {
        this.websiteService = websiteService;
        this.websiteRepository = websiteRepository;
        this.inspectionService = inspectionService;
        this.riskAnalyzer = riskAnalyzer;
        this.alertService = alertService;
    }

    @Transactional
    public ScanPipelineResult executeScanPipeline(Long websiteId) {
        Website website = websiteService.getWebsiteById(websiteId);
        log.info("Starting orchestrated end-to-end scan pipeline for: domain={}, id={}", website.getDomain(), websiteId);

        // Step 1: Perform TLS inspection & persist scan result and certificate
        TLSInspector.InspectionOutcome outcome = inspectionService.performScan(websiteId);
        TLSScanResult scan = outcome.scanResult();
        CertificateDetails cert = outcome.certificateDetails();

        // Step 2: Perform risk analysis & persist assessment and findings
        RiskAnalyzer.AnalysisResult analysis = riskAnalyzer.analyzeAndPersist(scan, cert);
        RiskAssessment risk = analysis.assessment();
        List<SecurityFinding> findings = analysis.findings();

        // Step 3: Process and dispatch alerts with deduplication
        List<Alert> alerts = alertService.processScanAlerts(website, scan, cert, risk);

        // Step 4: Update Website status based on findings & scan outcome
        if ("FAILED".equalsIgnoreCase(scan.getConnectionStatus())
                || "TIMEOUT".equalsIgnoreCase(scan.getConnectionStatus())
                || "CONNECTION_FAILED".equalsIgnoreCase(scan.getConnectionStatus())
                || "HANDSHAKE_FAILED".equalsIgnoreCase(scan.getConnectionStatus())) {
            website.setStatus("FAILED");
        } else if ("CRITICAL".equalsIgnoreCase(risk.getRiskLevel())) {
            website.setStatus("CRITICAL");
        } else if ("HIGH".equalsIgnoreCase(risk.getRiskLevel())) {
            website.setStatus("WARNING");
        } else {
            website.setStatus("ACTIVE");
        }
        website.setLastScannedAt(LocalDateTime.now());
        websiteRepository.save(website);

        log.info("Completed scan pipeline for {}: status={}, score={}/100, risk={}, alertsGenerated={}",
                website.getDomain(), website.getStatus(), risk.getTotalScore(), risk.getRiskLevel(), alerts.size());

        return new ScanPipelineResult(website, scan, cert, risk, findings, alerts);
    }
}
