package com.tlsmonitor.reporting;

import com.tlsmonitor.alerts.entity.Alert;
import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.reporting.service.ExcelReportService;
import com.tlsmonitor.risk.entity.RiskAssessment;
import com.tlsmonitor.risk.entity.SecurityFinding;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.ss.usermodel.WorkbookFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("ExcelReportService Unit Tests")
class ExcelReportServiceTest {

    private ExcelReportService excelReportService;

    @BeforeEach
    void setUp() {
        excelReportService = new ExcelReportService();
    }

    @Test
    @DisplayName("Should generate complete multi-sheet Excel workbook with formula injection sanitization")
    void shouldGenerateMultiSheetExcelWorkbook() throws Exception {
        Website website = new Website("=cmd|' /C calc'!A0", "https://example.com", "Formula test domain");
        website.setId(10L);
        website.setContactEmail("admin@example.com");

        TLSScanResult scan = new TLSScanResult();
        scan.setWebsiteId(10L);
        scan.setDomain("=cmd|' /C calc'!A0");
        scan.setPort(443);
        scan.setConnectionStatus("SUCCESS");
        scan.setTlsVersion("TLSv1.3");
        scan.setCipherSuite("TLS_AES_256_GCM_SHA384");
        scan.setHostnameValid(true);
        scan.setTrustChainValid(true);
        scan.setSupportedProtocols("TLSv1.3");
        scan.setResponseTimeMs(50);

        CertificateDetails cert = new CertificateDetails();
        cert.setWebsiteId(10L);
        cert.setSubject("CN=example.com");
        cert.setIssuer("CN=DigiCert Global Root CA");
        cert.setDaysRemaining(90);
        cert.setValidFrom(LocalDateTime.now().minusDays(10));
        cert.setValidUntil(LocalDateTime.now().plusDays(90));

        RiskAssessment assessment = new RiskAssessment(10L, 10L, 10, "LOW", 0);
        SecurityFinding finding = new SecurityFinding(10L, 10L, "SAFE_KEY", "No issues found", "Clean profile", "INFO", 0, "No issues", "Keep up to date");
        Alert alert = new Alert(10L, "example.com", "STATUS_OK", "INFO", "Everything nominal");

        byte[] excelBytes = excelReportService.generateWorkbook(
                List.of(website),
                List.of(scan),
                List.of(cert),
                List.of(assessment),
                List.of(finding),
                List.of(alert)
        );

        assertNotNull(excelBytes);
        assertTrue(excelBytes.length > 1000, "Workbook should not be empty");

        try (Workbook wb = WorkbookFactory.create(new ByteArrayInputStream(excelBytes))) {
            assertEquals(6, wb.getNumberOfSheets(), "Should contain exactly 6 sheets");

            Sheet sheet1 = wb.getSheet("Website Inventory");
            assertNotNull(sheet1);
            // Verify formula injection sanitization on '=cmd|' /C calc'!A0'
            String domainCell = sheet1.getRow(1).getCell(1).getStringCellValue();
            assertTrue(domainCell.startsWith("'="), "Formula prefix '=' should be sanitized with leading single quote: " + domainCell);

            assertNotNull(wb.getSheet("Certificate Details"));
            assertNotNull(wb.getSheet("TLS Inspections"));
            assertNotNull(wb.getSheet("Risk Assessments"));
            assertNotNull(wb.getSheet("Security Findings"));
            assertNotNull(wb.getSheet("Alert History"));
        }
    }

    @Test
    @DisplayName("Should generate empty sheets cleanly when input lists are empty")
    void shouldGenerateEmptyWorkbookCleanly() throws Exception {
        byte[] excelBytes = excelReportService.generateWorkbook(
                Collections.emptyList(),
                Collections.emptyList(),
                Collections.emptyList(),
                Collections.emptyList(),
                Collections.emptyList(),
                Collections.emptyList()
        );

        assertNotNull(excelBytes);
        try (Workbook wb = WorkbookFactory.create(new ByteArrayInputStream(excelBytes))) {
            assertEquals(6, wb.getNumberOfSheets());
            Sheet inventorySheet = wb.getSheet("Website Inventory");
            assertNotNull(inventorySheet);
            // Only header row should exist
            assertEquals(0, inventorySheet.getLastRowNum());
        }
    }
}
