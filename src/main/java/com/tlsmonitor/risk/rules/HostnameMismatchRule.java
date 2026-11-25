package com.tlsmonitor.risk.rules;

import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inspection.entity.ValidationStatus;
import com.tlsmonitor.risk.entity.SecurityFinding;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Component
public class HostnameMismatchRule implements RiskRule {

    @Override
    public String getRuleCode() {
        return "HOST_01";
    }

    @Override
    public String getRuleName() {
        return "Hostname Verification Rule";
    }

    @Override
    public List<SecurityFinding> evaluate(TLSScanResult scan, CertificateDetails cert) {
        if (scan == null || cert == null
                || scan.getHostnameValidationStatus() != ValidationStatus.INVALID) {
            return Collections.emptyList();
        }

        List<SecurityFinding> findings = new ArrayList<>();
        Long scanId = scan.getId() != null ? scan.getId() : 0L;
        Long websiteId = scan.getWebsiteId() != null ? scan.getWebsiteId() : 0L;

        String certSubject = cert.getSubject() != null ? cert.getSubject() : "N/A";
        String sans = cert.getSubjectAlternativeNames() != null ? cert.getSubjectAlternativeNames() : "N/A";

        findings.add(new SecurityFinding(
                scanId, websiteId, "HOST_MISMATCH",
                "Certificate Hostname Mismatch",
                "The certificate presented by the server does not match the requested hostname '" + scan.getDomain() + "'. This indicates potential misconfiguration or Man-in-the-Middle risk.",
                "HIGH", 40,
                "Target Domain: " + scan.getDomain() + " | Subject: " + certSubject + " | SANs: " + sans,
                "Re-issue certificate to include '" + scan.getDomain() + "' in the Subject Alternative Names (SAN)."
        ));
        return findings;
    }
}
