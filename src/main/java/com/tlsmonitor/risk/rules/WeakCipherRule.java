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
        if (scan == null || scan.getCipherSuite() == null || scan.getCipherSuite().isBlank()) {
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
                cipher.contains("MD5") ||
                cipher.contains("CBC");

        if (isWeak) {
            String reason = "weak or broken cryptography";
            if (cipher.contains("RC4")) reason = "broken RC4 stream cipher";
            else if (cipher.contains("3DES") || cipher.contains("DES")) reason = "vulnerable DES/3DES block cipher (Sweet32 attack)";
            else if (cipher.contains("NULL")) reason = "unencrypted plaintext NULL cipher";
            else if (cipher.contains("EXPORT")) reason = "insecure EXPORT-grade cryptography (FREAK/Logjam)";
            else if (cipher.contains("MD5")) reason = "broken MD5 hashing algorithm";
            else if (cipher.contains("CBC")) reason = "deprecated CBC-mode cipher vulnerable to padding oracle attacks";

            findings.add(new SecurityFinding(
                    scanId, websiteId, "CIPH_WEAK_SUITE",
                    "Weak Cipher Suite Negotiated",
                    "The negotiated cipher suite '" + scan.getCipherSuite() + "' uses " + reason + ".",
                    "HIGH", 20,
                    "Negotiated Cipher: " + scan.getCipherSuite(),
                    "Configure cipher suites that support AEAD encryption (such as AES-GCM or CHACHA20-POLY1305) with forward secrecy (ECDHE)."
            ));
        }

        return findings;
    }
}
