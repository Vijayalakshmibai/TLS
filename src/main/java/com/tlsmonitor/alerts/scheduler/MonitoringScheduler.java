package com.tlsmonitor.alerts.scheduler;

import com.tlsmonitor.config.AsyncConfig;
import com.tlsmonitor.inspection.service.ScanOrchestratorService;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.inventory.service.WebsiteService;
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
    private final ScanOrchestratorService scanOrchestratorService;
    private final Executor scanExecutor;

    public MonitoringScheduler(WebsiteService websiteService,
                               ScanOrchestratorService scanOrchestratorService,
                               @Qualifier(AsyncConfig.SCAN_EXECUTOR) Executor scanExecutor) {
        this.websiteService = websiteService;
        this.scanOrchestratorService = scanOrchestratorService;
        this.scanExecutor = scanExecutor;
    }

    // Cron default: Every day at 08:00 AM UTC
    @Scheduled(cron = "${monitoring.schedule.cron:0 0 8 * * *}")
    public void runScheduledMonitoring() {
        log.info("Starting scheduled TLS certificate & configuration monitoring cycle...");
        List<Website> activeWebsites = websiteService.getAllWebsites().stream()
                .filter(w -> !"DISABLED".equalsIgnoreCase(w.getStatus()))
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
        log.info("Scheduled task: Orchestrating scan for domain {}", website.getDomain());
        ScanOrchestratorService.ScanPipelineResult result = scanOrchestratorService.executeScanPipeline(website.getId());
        log.info("Scheduled task completed for {}: score={}, findings={}",
                website.getDomain(), result.riskAssessment().getTotalScore(), result.findings().size());
    }
}
