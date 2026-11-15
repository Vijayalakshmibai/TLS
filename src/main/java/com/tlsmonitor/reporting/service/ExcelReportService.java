package com.tlsmonitor.reporting.service;

import com.tlsmonitor.alerts.entity.Alert;
import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.risk.entity.RiskAssessment;
import com.tlsmonitor.risk.entity.SecurityFinding;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Service
public class ExcelReportService {

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public byte[] generateWorkbook(List<Website> websites,
                                   List<TLSScanResult> scans,
                                   List<CertificateDetails> certificates,
                                   List<RiskAssessment> assessments,
                                   List<SecurityFinding> findings,
                                   List<Alert> alerts) throws Exception {

        try (Workbook workbook = new XSSFWorkbook(); ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            CellStyle headerStyle = createHeaderStyle(workbook);

            // Sheet 1: Website Inventory
            Sheet sheet1 = workbook.createSheet("Website Inventory");
            String[] headers1 = {"ID", "Domain", "URL", "Port", "Status", "Created At", "Last Scanned"};
            createHeaderRow(sheet1, headers1, headerStyle);
            int rowIdx = 1;
            for (Website w : websites) {
                Row row = sheet1.createRow(rowIdx++);
                row.createCell(0).setCellValue(w.getId() != null ? w.getId() : 0);
                row.createCell(1).setCellValue(sanitize(w.getDomain()));
                row.createCell(2).setCellValue(sanitize(w.getUrl()));
                row.createCell(3).setCellValue(w.getPort());
                row.createCell(4).setCellValue(sanitize(w.getStatus()));
                row.createCell(5).setCellValue(w.getCreatedAt() != null ? w.getCreatedAt().format(FORMATTER) : "");
                row.createCell(6).setCellValue(w.getLastScannedAt() != null ? w.getLastScannedAt().format(FORMATTER) : "N/A");
            }
            autoSizeColumns(sheet1, headers1.length);

            // Sheet 2: Certificate Details
            Sheet sheet2 = workbook.createSheet("Certificate Details");
            String[] headers2 = {"Website ID", "Subject", "Issuer", "Serial", "Valid From", "Valid Until", "Days Remaining", "Expired", "Key Size", "Signature Alg", "Fingerprint"};
            createHeaderRow(sheet2, headers2, headerStyle);
            rowIdx = 1;
            for (CertificateDetails c : certificates) {
                Row row = sheet2.createRow(rowIdx++);
                row.createCell(0).setCellValue(c.getWebsiteId() != null ? c.getWebsiteId() : 0);
                row.createCell(1).setCellValue(sanitize(c.getSubject()));
                row.createCell(2).setCellValue(sanitize(c.getIssuer()));
                row.createCell(3).setCellValue(sanitize(c.getSerialNumber()));
                row.createCell(4).setCellValue(c.getValidFrom() != null ? c.getValidFrom().format(FORMATTER) : "");
                row.createCell(5).setCellValue(c.getValidUntil() != null ? c.getValidUntil().format(FORMATTER) : "");
                row.createCell(6).setCellValue(c.getDaysRemaining());
                row.createCell(7).setCellValue(c.isExpired() ? "YES" : "NO");
                row.createCell(8).setCellValue(c.getKeySize() + " bits");
                row.createCell(9).setCellValue(sanitize(c.getSignatureAlgorithm()));
                row.createCell(10).setCellValue(sanitize(c.getSha256Fingerprint()));
            }
            autoSizeColumns(sheet2, headers2.length);

            // Sheet 3: TLS Scans
            Sheet sheet3 = workbook.createSheet("TLS Inspections");
            String[] headers3 = {"Domain", "Status", "TLS Version", "Cipher Suite", "Hostname Valid", "Trust Chain Valid", "Supported Protocols", "Latency (ms)", "Scan Time"};
            createHeaderRow(sheet3, headers3, headerStyle);
            rowIdx = 1;
            for (TLSScanResult s : scans) {
                Row row = sheet3.createRow(rowIdx++);
                row.createCell(0).setCellValue(sanitize(s.getDomain()));
                row.createCell(1).setCellValue(sanitize(s.getConnectionStatus()));
                row.createCell(2).setCellValue(sanitize(s.getTlsVersion()));
                row.createCell(3).setCellValue(sanitize(s.getCipherSuite()));
                row.createCell(4).setCellValue(s.isHostnameValid() ? "VALID" : "MISMATCH");
                row.createCell(5).setCellValue(s.isTrustChainValid() ? "TRUSTED" : "UNTRUSTED");
                row.createCell(6).setCellValue(sanitize(s.getSupportedProtocols()));
                row.createCell(7).setCellValue(s.getResponseTimeMs());
                row.createCell(8).setCellValue(s.getScannedAt() != null ? s.getScannedAt().format(FORMATTER) : "");
            }
            autoSizeColumns(sheet3, headers3.length);

            // Sheet 4: Risk Assessments
            Sheet sheet4 = workbook.createSheet("Risk Assessments");
            String[] headers4 = {"Website ID", "Risk Score (0-100)", "Risk Level", "Issues Count", "Rule Version", "Assessed At"};
            createHeaderRow(sheet4, headers4, headerStyle);
            rowIdx = 1;
            for (RiskAssessment a : assessments) {
                Row row = sheet4.createRow(rowIdx++);
                row.createCell(0).setCellValue(a.getWebsiteId() != null ? a.getWebsiteId() : 0);
                row.createCell(1).setCellValue(a.getTotalScore());
                row.createCell(2).setCellValue(sanitize(a.getRiskLevel()));
                row.createCell(3).setCellValue(a.getFindingsCount());
                row.createCell(4).setCellValue(sanitize(a.getRuleSetVersion()));
                row.createCell(5).setCellValue(a.getAssessedAt() != null ? a.getAssessedAt().format(FORMATTER) : "");
            }
            autoSizeColumns(sheet4, headers4.length);

            // Sheet 5: Security Findings
            Sheet sheet5 = workbook.createSheet("Security Findings");
            String[] headers5 = {"Website ID", "Rule Code", "Severity", "Title", "Points", "Evidence", "Recommendation"};
            createHeaderRow(sheet5, headers5, headerStyle);
            rowIdx = 1;
            for (SecurityFinding f : findings) {
                Row row = sheet5.createRow(rowIdx++);
                row.createCell(0).setCellValue(f.getWebsiteId() != null ? f.getWebsiteId() : 0);
                row.createCell(1).setCellValue(sanitize(f.getRuleCode()));
                row.createCell(2).setCellValue(sanitize(f.getSeverity()));
                row.createCell(3).setCellValue(sanitize(f.getTitle()));
                row.createCell(4).setCellValue(f.getPoints());
                row.createCell(5).setCellValue(sanitize(f.getEvidence()));
                row.createCell(6).setCellValue(sanitize(f.getRecommendation()));
            }
            autoSizeColumns(sheet5, headers5.length);

            // Sheet 6: Alert History
            Sheet sheet6 = workbook.createSheet("Alert History");
            String[] headers6 = {"Domain", "Alert Type", "Severity", "Message", "Status", "Created At", "Sent At"};
            createHeaderRow(sheet6, headers6, headerStyle);
            rowIdx = 1;
            for (Alert al : alerts) {
                Row row = sheet6.createRow(rowIdx++);
                row.createCell(0).setCellValue(sanitize(al.getDomain()));
                row.createCell(1).setCellValue(sanitize(al.getAlertType()));
                row.createCell(2).setCellValue(sanitize(al.getSeverity()));
                row.createCell(3).setCellValue(sanitize(al.getMessage()));
                row.createCell(4).setCellValue(sanitize(al.getStatus()));
                row.createCell(5).setCellValue(al.getCreatedAt() != null ? al.getCreatedAt().format(FORMATTER) : "");
                row.createCell(6).setCellValue(al.getSentAt() != null ? al.getSentAt().format(FORMATTER) : "N/A");
            }
            autoSizeColumns(sheet6, headers6.length);

            workbook.write(out);
            return out.toByteArray();
        }
    }

    private CellStyle createHeaderStyle(Workbook wb) {
        CellStyle style = wb.createCellStyle();
        Font font = wb.createFont();
        font.setBold(true);
        font.setColor(IndexedColors.WHITE.getIndex());
        style.setFont(font);
        style.setFillForegroundColor(IndexedColors.DARK_BLUE.getIndex());
        style.setFillPattern(FillPatternType.SOLID_FOREGROUND);
        style.setAlignment(HorizontalAlignment.CENTER);
        return style;
    }

    private void createHeaderRow(Sheet sheet, String[] headers, CellStyle style) {
        Row row = sheet.createRow(0);
        for (int i = 0; i < headers.length; i++) {
            Cell cell = row.createCell(i);
            cell.setCellValue(headers[i]);
            cell.setCellStyle(style);
        }
    }

    private void autoSizeColumns(Sheet sheet, int numCols) {
        for (int i = 0; i < numCols; i++) {
            sheet.autoSizeColumn(i);
        }
    }

    private String sanitize(String input) {
        if (input == null) return "";
        // Prevent formula injection in spreadsheet software
        if (input.startsWith("=") || input.startsWith("+") || input.startsWith("-") || input.startsWith("@")) {
            return "'" + input;
        }
        return input;
    }
}
