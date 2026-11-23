package com.tlsmonitor.risk.rules;

import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.risk.entity.SecurityFinding;
import com.tlsmonitor.risk.service.ExpiryChecker;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Component
public class CertificateExpiryRule implements RiskRule {

    private final ExpiryChecker expiryChecker;

    public CertificateExpiryRule(ExpiryChecker expiryChecker) {
        this.expiryChecker = expiryChecker;
    }

    @Override
    public String getRuleCode() {
        return "EXP_01";
    }

    @Override
    public String getRuleName() {
        return "Certificate Expiration Rule";
    }

    @Override
    public List<SecurityFinding> evaluate(TLSScanResult scan, CertificateDetails cert) {
        if (cert == null || cert.getValidUntil() == null) {
            return Collections.emptyList();
        }

        List<SecurityFinding> findings = new ArrayList<>();
        Long scanId = scan.getId() != null ? scan.getId() : 0L;
        Long websiteId = scan.getWebsiteId() != null ? scan.getWebsiteId() : 0L;

        // Check if certificate is not yet valid (validity begins in the future)
        if (cert.isNotYetValid() || (cert.getValidFrom() != null && expiryChecker.isNotYetValid(cert.getValidFrom()))) {
            findings.add(new SecurityFinding(
                    scanId, websiteId, "EXP_NOT_YET_VALID",
                    "Certificate Not Yet Valid",
                    "The X.509 certificate validity period begins in the future (" + cert.getValidFrom() + " UTC). Browsers and clients will reject connections until this date.",
                    "CRITICAL", 40,
                    "Valid From: " + cert.getValidFrom() + " (UTC)",
                    "Verify system clock synchronization or wait until the certificate activation date before deploying."
            ));
        }

        long daysRemaining = expiryChecker.calculateRemainingDays(cert.getValidUntil());
        ExpiryChecker.ExpiryCategory category = expiryChecker.categorize(daysRemaining);

        switch (category) {
            case EXPIRED -> findings.add(new SecurityFinding(
                    scanId, websiteId, "EXP_EXPIRED",
                    "Certificate Expired",
                    "The X.509 certificate expired " + Math.abs(daysRemaining) + " days ago. Browsers and API clients will reject connections.",
                    "CRITICAL", 40,
                    "Expiry Date: " + cert.getValidUntil() + " (UTC)",
                    "Renew and deploy an active SSL/TLS certificate immediately."
            ));
            case CRITICAL -> findings.add(new SecurityFinding(
                    scanId, websiteId, "EXP_CRITICAL",
                    "Certificate Expiring within 7 Days",
                    "The certificate will expire in " + daysRemaining + " days. Immediate renewal is critical to prevent service outage.",
                    "CRITICAL", 30,
                    "Days Remaining: " + daysRemaining,
                    "Trigger automated or manual certificate renewal before the 7-day cutoff."
            ));
            case HIGH -> findings.add(new SecurityFinding(
                    scanId, websiteId, "EXP_HIGH",
                    "Certificate Expiring within 30 Days",
                    "The certificate will expire in " + daysRemaining + " days.",
                    "HIGH", 15,
                    "Days Remaining: " + daysRemaining,
                    "Schedule certificate renewal with your Certificate Authority."
            ));
            case MEDIUM -> findings.add(new SecurityFinding(
                    scanId, websiteId, "EXP_MEDIUM",
                    "Certificate Expiring within 60 Days",
                    "The certificate will expire in " + daysRemaining + " days.",
                    "MEDIUM", 10,
                    "Days Remaining: " + daysRemaining,
                    "Verify automated renewal pipelines are configured and operational."
            ));
            case LOW -> {
                // No risk finding if > 60 days
            }
        }

        return findings;
    }
}
