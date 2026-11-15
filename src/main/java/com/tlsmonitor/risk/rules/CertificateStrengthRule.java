package com.tlsmonitor.risk.rules;

import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.risk.entity.SecurityFinding;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Component
public class CertificateStrengthRule implements RiskRule {

    @Override
    public String getRuleCode() {
        return "STRENGTH_01";
    }

    @Override
    public String getRuleName() {
        return "Cryptographic Strength Rule";
    }

    @Override
    public List<SecurityFinding> evaluate(TLSScanResult scan, CertificateDetails cert) {
        if (cert == null) {
            return Collections.emptyList();
        }

        List<SecurityFinding> findings = new ArrayList<>();
        Long scanId = scan.getId() != null ? scan.getId() : 0L;
        Long websiteId = scan.getWebsiteId() != null ? scan.getWebsiteId() : 0L;

        String sigAlg = cert.getSignatureAlgorithm() != null ? cert.getSignatureAlgorithm().toUpperCase() : "";
        if (sigAlg.contains("SHA1") || sigAlg.contains("MD5") || sigAlg.contains("MD2")) {
            findings.add(new SecurityFinding(
                    scanId, websiteId, "SIG_WEAK_HASH",
                    "Weak Signature Algorithm Detected",
                    "The certificate was signed using a collision-vulnerable hash algorithm (" + cert.getSignatureAlgorithm() + ").",
                    "HIGH", 20,
                    "Signature Algorithm: " + cert.getSignatureAlgorithm(),
                    "Re-issue certificate using SHA-256 (or higher) with RSA or ECDSA."
            ));
        }

        if ("RSA".equalsIgnoreCase(cert.getPublicKeyAlgorithm()) && cert.getKeySize() > 0 && cert.getKeySize() < 2048) {
            findings.add(new SecurityFinding(
                    scanId, websiteId, "KEY_INSUFFICIENT_LENGTH",
                    "Insufficient RSA Key Length",
                    "The certificate uses an RSA key size of " + cert.getKeySize() + " bits. Modern cybersecurity standards require at least 2048 bits.",
                    "HIGH", 20,
                    "Key Size: " + cert.getKeySize() + " bits (RSA)",
                    "Generate a new private key with at least 2048 bits (or 4096 bits) or switch to ECDSA 256-bit."
            ));
        }

        return findings;
    }
}
