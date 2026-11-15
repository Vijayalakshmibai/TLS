package com.tlsmonitor.risk.rules;

import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.risk.entity.SecurityFinding;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Component
public class WeakProtocolRule implements RiskRule {

    @Override
    public String getRuleCode() {
        return "PROTO_01";
    }

    @Override
    public String getRuleName() {
        return "Weak TLS Protocol Rule";
    }

    @Override
    public List<SecurityFinding> evaluate(TLSScanResult scan, CertificateDetails cert) {
        if (scan == null) {
            return Collections.emptyList();
        }

        List<SecurityFinding> findings = new ArrayList<>();
        Long scanId = scan.getId() != null ? scan.getId() : 0L;
        Long websiteId = scan.getWebsiteId() != null ? scan.getWebsiteId() : 0L;

        if (scan.isWeakProtocolDetected()) {
            findings.add(new SecurityFinding(
                    scanId, websiteId, "PROTO_WEAK_VERSION",
                    "Deprecated TLS Protocol Enabled",
                    "The server supports legacy TLS 1.0 or TLS 1.1 protocols. These protocols are cryptographically obsolete and vulnerable to downgrade and CBC padding oracle attacks.",
                    "HIGH", 25,
                    "Supported Protocols: " + scan.getSupportedProtocols(),
                    "Disable TLS 1.0 and TLS 1.1 in your web server/reverse proxy configuration. Permit only TLS 1.2 and TLS 1.3."
            ));
        }

        return findings;
    }
}
