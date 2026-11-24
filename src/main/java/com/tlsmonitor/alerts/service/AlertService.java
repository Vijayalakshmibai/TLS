package com.tlsmonitor.alerts.service;

import com.tlsmonitor.alerts.entity.Alert;
import com.tlsmonitor.alerts.repository.AlertRepository;
import com.tlsmonitor.common.exception.ResourceNotFoundException;
import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.inventory.service.WebsiteService;
import com.tlsmonitor.risk.entity.RiskAssessment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Service
public class AlertService {

    private static final Logger log = LoggerFactory.getLogger(AlertService.class);

    private final AlertRepository alertRepository;
    private final EmailService emailService;
    private final WebsiteService websiteService;

    public AlertService(AlertRepository alertRepository, EmailService emailService, WebsiteService websiteService) {
        this.alertRepository = alertRepository;
        this.emailService = emailService;
        this.websiteService = websiteService;
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
        if (!scan.isHostnameValid()) {
            createDeduplicatedAlert(websiteId, domain, "HOSTNAME_MISMATCH", "HIGH",
                    "Certificate hostname mismatch detected for " + domain + ". Certificate does not cover this endpoint.", newAlerts);
        } else {
            resolveActiveAlerts(websiteId, "HOSTNAME_MISMATCH");
        }

        // 3. Untrusted Root / Broken Chain
        if (!scan.isTrustChainValid()) {
            createDeduplicatedAlert(websiteId, domain, "UNTRUSTED_CHAIN", "CRITICAL",
                    "Certificate trust validation failed for " + domain + ": " + scan.getTrustError(), newAlerts);
        } else {
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

    public List<Alert> getAllAlerts() {
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

    public long countActiveAlerts() {
        return alertRepository.countByStatus("PENDING") + alertRepository.countByStatus("SENT");
    }
}
