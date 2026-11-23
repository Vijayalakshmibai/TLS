package com.tlsmonitor.inspection.tls;

import com.tlsmonitor.inspection.entity.CertificateDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Component
public class CertificateExtractor {

    private static final Logger log = LoggerFactory.getLogger(CertificateExtractor.class);

    public CertificateDetails extractDetails(X509Certificate cert, Long scanId, Long websiteId, int chainLength) {
        CertificateDetails details = new CertificateDetails();
        details.setScanId(scanId);
        details.setWebsiteId(websiteId);
        details.setChainLength(chainLength);

        if (cert == null) {
            return details;
        }

        details.setSubject(cert.getSubjectX500Principal().getName());
        details.setIssuer(cert.getIssuerX500Principal().getName());
        details.setSerialNumber(cert.getSerialNumber().toString(16).toUpperCase());

        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        LocalDateTime notBefore = cert.getNotBefore().toInstant().atZone(ZoneOffset.UTC).toLocalDateTime();
        LocalDateTime notAfter = cert.getNotAfter().toInstant().atZone(ZoneOffset.UTC).toLocalDateTime();
        details.setValidFrom(notBefore);
        details.setValidUntil(notAfter);

        long daysRemaining = ChronoUnit.DAYS.between(now, notAfter);
        details.setDaysRemaining(daysRemaining);
        details.setExpired(now.isAfter(notAfter));
        details.setNotYetValid(now.isBefore(notBefore));

        details.setSignatureAlgorithm(cert.getSigAlgName());
        details.setPublicKeyAlgorithm(cert.getPublicKey().getAlgorithm());
        details.setKeySize(extractKeySize(cert));
        details.setSha256Fingerprint(computeSha256Fingerprint(cert));
        details.setSubjectAlternativeNames(extractSANs(cert));
        details.setSelfSigned(isSelfSigned(cert));

        return details;
    }

    public int extractKeySize(X509Certificate cert) {
        if (cert.getPublicKey() instanceof RSAPublicKey rsa) {
            return rsa.getModulus().bitLength();
        } else if (cert.getPublicKey() instanceof ECPublicKey ec) {
            return ec.getParams().getCurve().getField().getFieldSize();
        } else if (cert.getPublicKey() instanceof DSAPublicKey dsa) {
            return dsa.getParams().getP().bitLength();
        }
        return 0;
    }

    public String computeSha256Fingerprint(X509Certificate cert) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(cert.getEncoded());
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < digest.length; i++) {
                if (i > 0) sb.append(":");
                sb.append(String.format("%02X", digest[i]));
            }
            return sb.toString();
        } catch (CertificateEncodingException | java.security.NoSuchAlgorithmException e) {
            log.error("Failed to compute certificate fingerprint: {}", e.getMessage());
            return "UNKNOWN";
        }
    }

    public String extractSANs(X509Certificate cert) {
        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans == null || sans.isEmpty()) {
                return "";
            }
            List<String> names = new ArrayList<>();
            for (List<?> sanItem : sans) {
                if (sanItem.size() >= 2) {
                    Object val = sanItem.get(1);
                    if (val != null) {
                        names.add(val.toString());
                    }
                }
            }
            return String.join(", ", names);
        } catch (Exception e) {
            log.warn("Could not extract Subject Alternative Names: {}", e.getMessage());
            return "";
        }
    }

    public boolean isSelfSigned(X509Certificate cert) {
        try {
            if (!cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
                return false;
            }
            cert.verify(cert.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
