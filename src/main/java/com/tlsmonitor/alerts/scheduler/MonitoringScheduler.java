package com.tlsmonitor.alerts.scheduler;

import com.tlsmonitor.alerts.service.AlertService;
import com.tlsmonitor.config.AsyncConfig;
import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inspection.service.TLSInspectionService;
import com.tlsmonitor.inspection.tls.TLSInspector;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.inventory.service.WebsiteService;
import com.tlsmonitor.risk.entity.RiskAssessment;
import com.tlsmonitor.risk.service.RiskAnalyzer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.Executor;

@Component
public class MonitoringScheduler {

    private static final Logger log = LoggerFactory.getLogger(MonitoringScheduler.class);

    private final WebsiteService websiteService;
    private final TLSInspectionService inspectionService;
    private final RiskAnalyzer riskAnalyzer;
    private final AlertService alertService;
    private final Executor scanExecutor;

    public MonitoringScheduler(WebsiteService websiteService,
                               TLSInspectionService inspectionService,
                               RiskAnalyzer riskAnalyzer,
                               AlertService alertService,
                               @Qualifier(AsyncConfig.SCAN_EXECUTOR) Executor scanExecutor) {
        this.websiteService = websiteService;
        this.inspectionService = inspectionService;
        this.riskAnalyzer = riskAnalyzer;
        this.alertService = alertService;
        this.scanExecutor = scanExecutor;
    }

    // Cron default: Every day at 08:00 AM UTC
    @Scheduled(cron = "${monitoring.schedule.cron:0 0 8 * * *}")
    public void runScheduledMonitoring() {
        log.info("Starting scheduled TLS certificate & configuration monitoring cycle...");
        List<Website> activeWebsites = websiteService.getAllWebsites().stream()
                .filter(w -> "ACTIVE".equalsIgnoreCase(w.getStatus()))
                .toList();

        log.info("Found {} active websites to monitor.", activeWebsites.size());

        for (Website website : activeWebsites) {
            scanExecutor.execute(() -> {
                try {
                    processWebsiteScan(website);
                } catch (Exception e) {
                    log.error("Scheduled scan failed for {}: {}", website.getDomain(), e.getMessage());
                }
            });
        }
    }

    public void processWebsiteScan(Website website) {
        log.info("Scheduled task: Scanning domain {}", website.getDomain());
        TLSInspector.InspectionOutcome outcome = inspectionService.performScan(website.getId());
        TLSScanResult scan = outcome.scanResult();
        CertificateDetails cert = outcome.certificateDetails();

        RiskAnalyzer.AnalysisResult analysis = riskAnalyzer.analyzeAndPersist(scan, cert);
        RiskAssessment risk = analysis.assessment();

        alertService.processScanAlerts(website, scan, cert, risk);
        log.info("Scheduled task completed for {}: score={}, findings={}",
                website.getDomain(), risk.getTotalScore(), analysis.findings().size());
    }
}
