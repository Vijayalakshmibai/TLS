package com.tlsmonitor.reporting.service;

import com.lowagie.text.*;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.risk.entity.RiskAssessment;
import com.tlsmonitor.risk.entity.SecurityFinding;
import org.springframework.stereotype.Service;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Service
public class PdfReportService {

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public byte[] generateWebsiteReport(Website website,
                                        TLSScanResult scan,
                                        CertificateDetails cert,
                                        RiskAssessment risk,
                                        List<SecurityFinding> findings) throws Exception {

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Document document = new Document(PageSize.A4, 36, 36, 36, 36);
        PdfWriter.getInstance(document, out);
        document.open();

        Font titleFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 18, new Color(30, 58, 138));
        Font sectionFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 12, new Color(30, 58, 138));
        Font boldFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 9, Color.BLACK);
        Font normalFont = FontFactory.getFont(FontFactory.HELVETICA, 9, new Color(51, 65, 85));
        Font footerFont = FontFactory.getFont(FontFactory.HELVETICA_OBLIQUE, 8, Color.GRAY);

        // Header
        Paragraph title = new Paragraph("Fresh TLS Certificate & Security Audit Report", titleFont);
        title.setAlignment(Element.ALIGN_CENTER);
        document.add(title);

        Paragraph sub = new Paragraph("Generated on: " + LocalDateTime.now().format(FORMATTER) + " UTC | Confidential Security Assessment", footerFont);
        sub.setAlignment(Element.ALIGN_CENTER);
        sub.setSpacingAfter(15);
        document.add(sub);

        // Target Overview Table
        document.add(new Paragraph("1. Monitored Target Profile", sectionFont));
        PdfPTable targetTable = new PdfPTable(2);
        targetTable.setWidthPercentage(100);
        targetTable.setSpacingBefore(6);
        targetTable.setSpacingAfter(12);

        addTableRow(targetTable, "Target Domain:", website.getDomain(), boldFont, normalFont);
        addTableRow(targetTable, "Target URL:", website.getUrl(), boldFont, normalFont);
        addTableRow(targetTable, "Resolved IP Address:", scan != null && scan.getResolvedIp() != null ? scan.getResolvedIp() : "N/A", boldFont, normalFont);
        addTableRow(targetTable, "Port / Monitoring Status:", website.getPort() + " / " + website.getStatus(), boldFont, normalFont);
        document.add(targetTable);

        // TLS Connection Configuration
        document.add(new Paragraph("2. TLS & Handshake Security", sectionFont));
        PdfPTable tlsTable = new PdfPTable(2);
        tlsTable.setWidthPercentage(100);
        tlsTable.setSpacingBefore(6);
        tlsTable.setSpacingAfter(12);

        if (scan != null) {
            addTableRow(tlsTable, "Connection Status:", scan.getConnectionStatus(), boldFont, normalFont);
            addTableRow(tlsTable, "Negotiated TLS Version:", scan.getTlsVersion() != null ? scan.getTlsVersion() : "N/A", boldFont, normalFont);
            addTableRow(tlsTable, "Negotiated Cipher Suite:", scan.getCipherSuite() != null ? scan.getCipherSuite() : "N/A", boldFont, normalFont);
            addTableRow(tlsTable, "Hostname Validation:", scan.isHostnameValid() ? "PASS (Matches Domain)" : "FAIL (Hostname Mismatch)", boldFont, normalFont);
            addTableRow(tlsTable, "Trust Chain Validation:", scan.isTrustChainValid() ? "PASS (Trusted Root CA)" : "FAIL (" + scan.getTrustError() + ")", boldFont, normalFont);
            addTableRow(tlsTable, "Supported Protocols:", scan.getSupportedProtocols() != null ? scan.getSupportedProtocols() : "N/A", boldFont, normalFont);
            addTableRow(tlsTable, "Handshake Latency:", scan.getResponseTimeMs() + " ms", boldFont, normalFont);
        } else {
            addTableRow(tlsTable, "Status:", "No inspection data available", boldFont, normalFont);
        }
        document.add(tlsTable);

        // Certificate Details
        document.add(new Paragraph("3. X.509 Certificate Metadata", sectionFont));
        PdfPTable certTable = new PdfPTable(2);
        certTable.setWidthPercentage(100);
        certTable.setSpacingBefore(6);
        certTable.setSpacingAfter(12);

        if (cert != null) {
            addTableRow(certTable, "Subject DN:", cert.getSubject(), boldFont, normalFont);
            addTableRow(certTable, "Issuer CA:", cert.getIssuer(), boldFont, normalFont);
            addTableRow(certTable, "Validity Range (UTC):", cert.getValidFrom() + " to " + cert.getValidUntil(), boldFont, normalFont);
            addTableRow(certTable, "Days Remaining:", cert.getDaysRemaining() + " days " + (cert.isExpired() ? "[EXPIRED]" : ""), boldFont, normalFont);
            addTableRow(certTable, "Key Algorithm & Size:", cert.getPublicKeyAlgorithm() + " (" + cert.getKeySize() + " bits)", boldFont, normalFont);
            addTableRow(certTable, "Signature Algorithm:", cert.getSignatureAlgorithm(), boldFont, normalFont);
            addTableRow(certTable, "Serial Number:", cert.getSerialNumber(), boldFont, normalFont);
            addTableRow(certTable, "SHA-256 Fingerprint:", cert.getSha256Fingerprint(), boldFont, normalFont);
            addTableRow(certTable, "Alternative Names (SAN):", cert.getSubjectAlternativeNames() != null ? cert.getSubjectAlternativeNames() : "N/A", boldFont, normalFont);
        } else {
            addTableRow(certTable, "Certificate:", "No certificate data available", boldFont, normalFont);
        }
        document.add(certTable);

        // Risk Assessment & Findings
        document.add(new Paragraph("4. Risk Assessment & Findings", sectionFont));
        if (risk != null) {
            Paragraph riskScoreP = new Paragraph("Overall Risk Score: " + risk.getTotalScore() + "/100 (" + risk.getRiskLevel() + " SEVERITY)", boldFont);
            riskScoreP.setSpacingBefore(4);
            riskScoreP.setSpacingAfter(8);
            document.add(riskScoreP);
        }

        if (findings != null && !findings.isEmpty()) {
            PdfPTable findingsTable = new PdfPTable(4);
            findingsTable.setWidthPercentage(100);
            findingsTable.setWidths(new float[]{15, 25, 30, 30});
            findingsTable.setSpacingBefore(6);
            findingsTable.setSpacingAfter(14);

            addTableHeader(findingsTable, "Severity", boldFont);
            addTableHeader(findingsTable, "Rule & Issue", boldFont);
            addTableHeader(findingsTable, "Evidence", boldFont);
            addTableHeader(findingsTable, "Recommendation", boldFont);

            for (SecurityFinding f : findings) {
                findingsTable.addCell(new Phrase(f.getSeverity(), normalFont));
                findingsTable.addCell(new Phrase(f.getRuleCode() + ": " + f.getTitle(), normalFont));
                findingsTable.addCell(new Phrase(f.getEvidence() != null ? f.getEvidence() : "", normalFont));
                findingsTable.addCell(new Phrase(f.getRecommendation() != null ? f.getRecommendation() : "", normalFont));
            }
            document.add(findingsTable);
        } else {
            Paragraph noIssues = new Paragraph("No security findings or configuration risks detected.", normalFont);
            noIssues.setSpacingAfter(10);
            document.add(noIssues);
        }

        // Disclaimer
        Paragraph disclaimer = new Paragraph("Disclaimer: This security assessment was generated by Fresh TLS Monitor using active TLS handshake inspection. It evaluates cryptographic configurations based on established security baselines and does not constitute a full penetration test.", footerFont);
        disclaimer.setSpacingBefore(15);
        document.add(disclaimer);

        document.close();
        return out.toByteArray();
    }

    private void addTableRow(PdfPTable table, String header, String value, Font hFont, Font vFont) {
        PdfPCell c1 = new PdfPCell(new Phrase(header, hFont));
        c1.setBackgroundColor(new Color(248, 250, 252));
        c1.setPadding(4);
        PdfPCell c2 = new PdfPCell(new Phrase(value != null ? value : "N/A", vFont));
        c2.setPadding(4);
        table.addCell(c1);
        table.addCell(c2);
    }

    private void addTableHeader(PdfPTable table, String title, Font font) {
        PdfPCell cell = new PdfPCell(new Phrase(title, font));
        cell.setBackgroundColor(new Color(226, 232, 240));
        cell.setPadding(5);
        table.addCell(cell);
    }
}
