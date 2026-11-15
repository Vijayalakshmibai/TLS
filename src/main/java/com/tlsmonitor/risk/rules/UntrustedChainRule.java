package com.tlsmonitor.risk.rules;

import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.risk.entity.SecurityFinding;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Component
public class UntrustedChainRule implements RiskRule {

    @Override
    public String getRuleCode() {
        return "TRUST_01";
    }

    @Override
    public String getRuleName() {
        return "Trust Chain Validation Rule";
    }

    @Override
    public List<SecurityFinding> evaluate(TLSScanResult scan, CertificateDetails cert) {
        if (scan == null || "DNS_RESOLUTION_FAILED".equals(scan.getConnectionStatus())) {
            return Collections.emptyList();
        }

        List<SecurityFinding> findings = new ArrayList<>();
        Long scanId = scan.getId() != null ? scan.getId() : 0L;
        Long websiteId = scan.getWebsiteId() != null ? scan.getWebsiteId() : 0L;

        if (!scan.isTrustChainValid()) {
            boolean isSelfSigned = cert != null && cert.isSelfSigned();
            String title = isSelfSigned ? "Self-Signed Certificate Detected" : "Untrusted Certificate Chain";
            String severity = "CRITICAL";
            int points = isSelfSigned ? 25 : 35;
            String errorMsg = scan.getTrustError() != null ? scan.getTrustError() : "Failed to establish trust path to a recognized Certificate Authority";

            findings.add(new SecurityFinding(
                    scanId, websiteId, isSelfSigned ? "TRUST_SELF_SIGNED" : "TRUST_INVALID_CHAIN",
                    title,
                    "The certificate could not be validated against the standard Root CA trust store: " + errorMsg,
                    severity, points,
                    "Trust Error: " + errorMsg,
                    "Install intermediate certificates on the web server or obtain a certificate from a trusted public CA (e.g. Let's Encrypt, DigiCert)."
            ));
        }

        return findings;
    }
}
