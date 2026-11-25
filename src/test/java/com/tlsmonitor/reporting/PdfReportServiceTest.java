package com.tlsmonitor.reporting;

import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.reporting.service.PdfReportService;
import com.tlsmonitor.risk.entity.RiskAssessment;
import com.tlsmonitor.risk.entity.SecurityFinding;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.parser.PdfTextExtractor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("PdfReportService Unit Tests")
class PdfReportServiceTest {

    private PdfReportService pdfReportService;

    @BeforeEach
    void setUp() {
        pdfReportService = new PdfReportService();
    }

    @Test
    @DisplayName("Should generate valid PDF document with %PDF magic header")
    void shouldGenerateValidPdfDocument() throws Exception {
        Website website = new Website("google.com", "https://google.com", "Main production domain");
        website.setId(1L);
        website.setContactEmail("admin@example.com");

        TLSScanResult scan = new TLSScanResult();
        scan.setWebsiteId(1L);
        scan.setDomain("google.com");
        scan.setPort(443);
        scan.setConnectionStatus("SUCCESS");
        scan.setTlsVersion("TLSv1.3");
        scan.setCipherSuite("TLS_AES_128_GCM_SHA256");
        scan.setHostnameValid(true);
        scan.setTrustChainValid(true);
        scan.setSupportedProtocols("TLSv1.2, TLSv1.3");
        scan.setResponseTimeMs(45);
        scan.setResolvedIp("142.250.190.46");

        CertificateDetails cert = new CertificateDetails();
        cert.setWebsiteId(1L);
        cert.setSubject("CN=google.com");
        cert.setIssuer("CN=GTS CA 1C3, O=Google Trust Services LLC, C=US");
        cert.setSerialNumber("1234567890ABCDEF");
        cert.setSignatureAlgorithm("SHA256withRSA");
        cert.setPublicKeyAlgorithm("RSA");
        cert.setKeySize(2048);
        cert.setDaysRemaining(75);
        cert.setExpired(false);
        cert.setSelfSigned(false);
        cert.setValidFrom(LocalDateTime.now().minusDays(15));
        cert.setValidUntil(LocalDateTime.now().plusDays(75));
        cert.setSha256Fingerprint("AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99");

        RiskAssessment risk = new RiskAssessment(1L, 1L, 15, "LOW", 1);
        SecurityFinding finding = new SecurityFinding(1L, 1L, "INFO_KEY", "Standard 2048-bit key", "RSA Key is 2048 bits", "INFO", 5, "Key length 2048", "Consider ECDSA P-256 for forward secrecy");

        byte[] pdfBytes = pdfReportService.generateWebsiteReport(website, scan, cert, risk, List.of(finding));

        assertNotNull(pdfBytes, "PDF byte array should not be null");
        assertTrue(pdfBytes.length > 500, "PDF should have meaningful length");

        // Verify PDF Magic Bytes (%PDF-...)
        assertEquals('%', (char) pdfBytes[0]);
        assertEquals('P', (char) pdfBytes[1]);
        assertEquals('D', (char) pdfBytes[2]);
        assertEquals('F', (char) pdfBytes[3]);
    }

    @Test
    @DisplayName("Should generate valid PDF gracefully when scan details and risk assessment are null")
    void shouldGeneratePdfGracefullyWithNullComponents() throws Exception {
        Website website = new Website("unreachable.test", "https://unreachable.test", "Test host");
        website.setId(2L);

        byte[] pdfBytes = pdfReportService.generateWebsiteReport(website, null, null, null, Collections.emptyList());

        assertNotNull(pdfBytes);
        assertTrue(pdfBytes.length > 500);
        assertEquals('%', (char) pdfBytes[0]);
        assertEquals('P', (char) pdfBytes[1]);
        assertEquals('D', (char) pdfBytes[2]);
        assertEquals('F', (char) pdfBytes[3]);
    }

    @Test
    @DisplayName("Should report unavailable TLS validations as not evaluated")
    void shouldMarkUnavailableValidationAsNotEvaluated() throws Exception {
        Website website = new Website("reset.test", "https://reset.test", "Connection reset before TLS certificate");
        website.setId(3L);

        TLSScanResult scan = new TLSScanResult();
        scan.setWebsiteId(3L);
        scan.setDomain("reset.test");
        scan.setConnectionStatus("CONNECTION_FAILED");

        byte[] pdfBytes = pdfReportService.generateWebsiteReport(website, scan, null, null, Collections.emptyList());
        PdfReader reader = new PdfReader(pdfBytes);
        String reportText = new PdfTextExtractor(reader).getTextFromPage(1);
        reader.close();

        assertTrue(reportText.contains("Hostname Validation:"));
        assertTrue(reportText.contains("Trust Chain Validation:"));
        assertEquals(2, reportText.split("NOT EVALUATED", -1).length - 1);
        assertFalse(reportText.contains("FAIL (Hostname Mismatch)"));
        assertFalse(reportText.contains("FAIL (Untrusted certificate chain)"));
    }
}
