package com.tlsmonitor.risk.rules;

import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.risk.entity.SecurityFinding;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Component
public class WeakCipherRule implements RiskRule {

    @Override
    public String getRuleCode() {
        return "CIPH_01";
    }

    @Override
    public String getRuleName() {
        return "Weak Cipher Suite Rule";
    }

    @Override
    public List<SecurityFinding> evaluate(TLSScanResult scan, CertificateDetails cert) {
        if (scan == null || scan.getCipherSuite() == null) {
            return Collections.emptyList();
        }

        List<SecurityFinding> findings = new ArrayList<>();
        Long scanId = scan.getId() != null ? scan.getId() : 0L;
        Long websiteId = scan.getWebsiteId() != null ? scan.getWebsiteId() : 0L;

        String cipher = scan.getCipherSuite().toUpperCase();

        boolean isWeak = cipher.contains("RC4") ||
                cipher.contains("3DES") ||
                cipher.contains("DES") ||
                cipher.contains("NULL") ||
                cipher.contains("EXPORT") ||
                cipher.contains("MD5");

        if (isWeak) {
            findings.add(new SecurityFinding(
                    scanId, websiteId, "CIPH_WEAK_SUITE",
                    "Weak Cipher Suite Negotiated",
                    "The negotiated cipher suite '" + scan.getCipherSuite() + "' uses weak or broken cryptography (e.g., 3DES/RC4/MD5).",
                    "HIGH", 20,
                    "Negotiated Cipher: " + scan.getCipherSuite(),
                    "Configure cipher suites that support AEAD encryption (such as AES-GCM or CHACHA20-POLY1305) with forward secrecy (ECDHE)."
            ));
        }

        return findings;
    }
}
