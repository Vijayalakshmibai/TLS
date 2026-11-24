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

        boolean isNegotiatedWeak = isOutdatedProtocol(scan.getTlsVersion());
        boolean isSupportedWeak = scan.isWeakProtocolDetected() || containsOutdatedProtocol(scan.getSupportedProtocols());

        if (isNegotiatedWeak || isSupportedWeak) {
            String evidence = "Negotiated: " + (scan.getTlsVersion() != null ? scan.getTlsVersion() : "N/A")
                    + "; Supported: " + (scan.getSupportedProtocols() != null ? scan.getSupportedProtocols() : "N/A");

            findings.add(new SecurityFinding(
                    scanId, websiteId, "PROTO_WEAK_VERSION",
                    "Deprecated TLS Protocol Enabled",
                    "The server supports or negotiated legacy TLS 1.0 or TLS 1.1 protocols. These protocols are cryptographically obsolete and vulnerable to downgrade and CBC padding oracle attacks.",
                    "HIGH", 25,
                    evidence,
                    "Disable TLS 1.0 and TLS 1.1 in your web server/reverse proxy configuration. Permit only TLS 1.2 and TLS 1.3."
            ));
        }

        return findings;
    }

    private boolean isOutdatedProtocol(String protocol) {
        if (protocol == null || protocol.isBlank()) {
            return false;
        }
        String p = protocol.trim().toUpperCase();
        return p.equals("TLSV1") || p.equals("TLSV1.0") || p.equals("TLSV1.1")
                || p.equals("SSLV3") || p.equals("SSLV2") || p.equals("SSLV2HELLO");
    }

    private boolean containsOutdatedProtocol(String supportedProtocols) {
        if (supportedProtocols == null || supportedProtocols.isBlank()) {
            return false;
        }
        String p = supportedProtocols.toUpperCase();
        return p.contains("TLSV1.0") || p.contains("TLSV1.1")
                || p.contains("TLSV1,") || p.endsWith("TLSV1") || p.contains("TLSV1 ")
                || p.contains("SSLV3");
    }
}
