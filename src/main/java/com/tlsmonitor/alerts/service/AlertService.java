package com.tlsmonitor.alerts.service;

import com.tlsmonitor.alerts.entity.Alert;
import com.tlsmonitor.alerts.repository.AlertRepository;
import com.tlsmonitor.common.exception.ResourceNotFoundException;
import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inspection.entity.ValidationStatus;
import com.tlsmonitor.inspection.repository.CertificateDetailsRepository;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.inventory.repository.WebsiteRepository;
import com.tlsmonitor.reporting.service.PdfReportService;
import com.tlsmonitor.risk.entity.RiskAssessment;
import com.tlsmonitor.risk.entity.SecurityFinding;
import com.tlsmonitor.risk.service.RiskReportResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class AlertService {

    private static final Logger log = LoggerFactory.getLogger(AlertService.class);

    private final AlertRepository alertRepository;
    private final EmailService emailService;
    private final WebsiteRepository websiteRepository;
    private final CertificateDetailsRepository certRepository;
    private final RiskReportResolver riskReportResolver;
    private final PdfReportService pdfReportService;
    private final String reportRecipient;

    @Autowired
    public AlertService(AlertRepository alertRepository,
                        EmailService emailService,
                        WebsiteRepository websiteRepository,
                        CertificateDetailsRepository certRepository,
                        @Lazy RiskReportResolver riskReportResolver,
                        PdfReportService pdfReportService,
                        @Value("${app.alerts.report-recipient:vijayalakshmibai0686@gmail.com}") String reportRecipient) {
        this.alertRepository = alertRepository;
        this.emailService = emailService;
        this.websiteRepository = websiteRepository;
        this.certRepository = certRepository;
        this.riskReportResolver = riskReportResolver;
        this.pdfReportService = pdfReportService;
        this.reportRecipient = reportRecipient;
    }

    public AlertService(AlertRepository alertRepository,
                        EmailService emailService,
                        WebsiteRepository websiteRepository) {
        this(alertRepository, emailService, websiteRepository, null, null, null, "vijayalakshmibai0686@gmail.com");
    }

    @Transactional
    public List<Alert> processScanAlerts(Website website, TLSScanResult scan, CertificateDetails cert, RiskAssessment risk) {
        List<Alert> newAlerts = new ArrayList<>();

        if (website == null || scan == null) {
            return newAlerts;
        }

        Long websiteId = website.getId();
        String domain = website.getDomain();

        // 1. Certificate Expiry Checks
        if (cert != null) {
            if (cert.isExpired()) {
                createDeduplicatedAlert(websiteId, domain, "EXPIRED", "CRITICAL",
                        "SSL/TLS certificate for " + domain + " has expired! Service is currently degraded or inaccessible.", newAlerts);
            } else {
                resolveActiveAlerts(websiteId, "EXPIRED");

                if (cert.getDaysRemaining() <= 7) {
                    createDeduplicatedAlert(websiteId, domain, "EXPIRY_WARNING_7D", "CRITICAL",
                            "Certificate for " + domain + " expires in " + cert.getDaysRemaining() + " days. Immediate renewal required.", newAlerts);
                } else {
                    resolveActiveAlerts(websiteId, "EXPIRY_WARNING_7D");

                    if (cert.getDaysRemaining() <= 30) {
                        createDeduplicatedAlert(websiteId, domain, "EXPIRY_WARNING_30D", "HIGH",
                                "Certificate for " + domain + " expires in " + cert.getDaysRemaining() + " days. Renewal scheduled.", newAlerts);
                    } else {
                        resolveActiveAlerts(websiteId, "EXPIRY_WARNING_30D");
                    }
                }
            }
        }

        // 2. Hostname Mismatch
        if (cert != null && scan.getHostnameValidationStatus() == ValidationStatus.INVALID) {
            createDeduplicatedAlert(websiteId, domain, "HOSTNAME_MISMATCH", "HIGH",
                    "Certificate hostname mismatch detected for " + domain + ". Certificate does not cover this endpoint.", newAlerts);
        } else if (scan.getHostnameValidationStatus() == ValidationStatus.VALID) {
            resolveActiveAlerts(websiteId, "HOSTNAME_MISMATCH");
        }

        // 3. Untrusted Root / Broken Chain
        if (cert != null && scan.getTrustValidationStatus() == ValidationStatus.INVALID) {
            createDeduplicatedAlert(websiteId, domain, "UNTRUSTED_CHAIN", "CRITICAL",
                    "Certificate trust validation failed for " + domain + ": " + scan.getTrustError(), newAlerts);
        } else if (scan.getTrustValidationStatus() == ValidationStatus.VALID) {
            resolveActiveAlerts(websiteId, "UNTRUSTED_CHAIN");
        }

        // 4. Critical Overall Risk
        if (risk != null && "CRITICAL".equalsIgnoreCase(risk.getRiskLevel())) {
            createDeduplicatedAlert(websiteId, domain, "CRITICAL_RISK", "CRITICAL",
                    "Target " + domain + " received a CRITICAL security risk score of " + risk.getTotalScore() + "/100.", newAlerts);
        } else {
            resolveActiveAlerts(websiteId, "CRITICAL_RISK");
        }

        // Send notifications for generated alerts
        for (Alert alert : newAlerts) {
            String contact = website.getContactEmail();
            if (contact != null && !contact.trim().isEmpty()) {
                boolean sent = emailService.sendAlertEmail(contact, alert);
                if (sent) {
                    alert.setStatus("SENT");
                    alert.setSentAt(LocalDateTime.now());
                    alertRepository.save(alert);
                }
            }
        }

        return newAlerts;
    }

    private void createDeduplicatedAlert(Long websiteId, String domain, String alertType, String severity, String message, List<Alert> collector) {
        boolean activeExists = alertRepository.existsByWebsiteIdAndAlertTypeAndStatus(websiteId, alertType, "PENDING") ||
                alertRepository.existsByWebsiteIdAndAlertTypeAndStatus(websiteId, alertType, "SENT");

        if (!activeExists) {
            Alert alert = new Alert(websiteId, domain, alertType, severity, message);
            Alert saved = alertRepository.save(alert);
            collector.add(saved);
            log.info("Created new alert ID {}: type={}, domain={}, severity={}", saved.getId(), alertType, domain, severity);
        } else {
            log.debug("Deduplicated alert for domain={}, type={} (already pending or sent)", domain, alertType);
        }
    }

    public void resolveActiveAlerts(Long websiteId, String alertType) {
        List<Alert> activeAlerts = alertRepository.findByWebsiteIdAndAlertTypeAndStatusNot(websiteId, alertType, "RESOLVED");
        for (Alert alert : activeAlerts) {
            alert.setStatus("RESOLVED");
            alert.setResolvedAt(LocalDateTime.now());
            alertRepository.save(alert);
            log.info("Auto-resolved active alert ID {} (type={}, websiteId={}) because security condition has been remediated.",
                    alert.getId(), alertType, websiteId);
        }
    }

    @Transactional
    public void resolveActiveAlertsForWebsite(Long websiteId) {
        List<Alert> activeAlerts = alertRepository.findByWebsiteIdAndStatusNot(websiteId, "RESOLVED");
        for (Alert alert : activeAlerts) {
            alert.setStatus("RESOLVED");
            alert.setResolvedAt(LocalDateTime.now());
            alertRepository.save(alert);
            log.info("Resolved alert ID {} because website ID {} was removed from monitoring.",
                    alert.getId(), websiteId);
        }
    }

    @Transactional
    public List<Alert> getAllAlerts() {
        resolveOrphanedAlerts();
        return alertRepository.findAllByOrderByCreatedAtDesc();
    }

    public List<Alert> getAlertsForWebsite(Long websiteId) {
        return alertRepository.findByWebsiteIdOrderByCreatedAtDesc(websiteId);
    }

    @Transactional
    public Alert acknowledgeAlert(Long id) {
        Alert alert = alertRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Alert not found with ID: " + id));
        alert.setStatus("ACKNOWLEDGED");
        return alertRepository.save(alert);
    }

    @Transactional
    public Alert resolveAlert(Long id) {
        Alert alert = alertRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Alert not found with ID: " + id));
        alert.setStatus("RESOLVED");
        alert.setResolvedAt(LocalDateTime.now());
        return alertRepository.save(alert);
    }

    /**
     * Generates a PDF security report for the alert's website and emails it to the
     * configured backend recipient. Records delivery status and timestamp on the alert.
     */
    @Transactional
    public boolean sendAlertPdfReport(Long alertId) {
        Alert alert = alertRepository.findById(alertId)
                .orElseThrow(() -> new ResourceNotFoundException("Alert not found with ID: " + alertId));

        Website website = websiteRepository.findById(alert.getWebsiteId())
                .orElseThrow(() -> new ResourceNotFoundException("Website not found with ID: " + alert.getWebsiteId()));

        RiskReportResolver.ResolvedRisk resolved = (riskReportResolver != null)
                ? riskReportResolver.resolve(website.getId()).orElse(null)
                : null;
        TLSScanResult scan = (resolved != null) ? resolved.scan() : null;
        CertificateDetails cert = (resolved != null) ? resolved.certificate()
                : (certRepository != null ? certRepository.findFirstByWebsiteIdOrderByIdDesc(website.getId()).orElse(null) : null);
        RiskAssessment risk = (resolved != null) ? resolved.assessment() : null;
        List<SecurityFinding> findings = (resolved != null) ? resolved.findings() : List.of();

        boolean sent = false;
        try {
            byte[] pdfBytes = pdfReportService.generateWebsiteReport(website, scan, cert, risk, findings);
            String fileName = "TLS_Security_Report_" + website.getDomain() + ".pdf";
            sent = emailService.sendPdfReportEmail(reportRecipient, alert, pdfBytes, fileName);
        } catch (Exception e) {
            log.error("Failed to generate or email PDF report for alert ID {} ({}): {}",
                    alertId, website.getDomain(), e.getMessage(), e);
        }

        alert.setReportDeliveryStatus(sent ? "SENT" : "FAILED");
        if (sent) {
            LocalDateTime now = LocalDateTime.now();
            alert.setReportSentAt(now);
            if ("PENDING".equalsIgnoreCase(alert.getStatus())) {
                alert.setStatus("SENT");
                alert.setSentAt(now);
            }
        }
        alertRepository.save(alert);
        return sent;
    }

    @Transactional
    public long countActiveAlerts() {
        resolveOrphanedAlerts();
        return alertRepository.countByStatus("PENDING") + alertRepository.countByStatus("SENT");
    }

    private void resolveOrphanedAlerts() {
        Set<Long> monitoredWebsiteIds = websiteRepository.findAll().stream()
                .map(Website::getId)
                .collect(Collectors.toSet());
        List<Alert> unresolvedAlerts = alertRepository.findByStatusNot("RESOLVED");
        for (Alert alert : unresolvedAlerts) {
            if (!monitoredWebsiteIds.contains(alert.getWebsiteId())) {
                alert.setStatus("RESOLVED");
                alert.setResolvedAt(LocalDateTime.now());
                alertRepository.save(alert);
                log.info("Resolved orphaned alert ID {} for deleted website ID {}.",
                        alert.getId(), alert.getWebsiteId());
            }
        }
    }
}
