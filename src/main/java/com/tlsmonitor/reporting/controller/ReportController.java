package com.tlsmonitor.reporting.controller;

import com.tlsmonitor.alerts.entity.Alert;
import com.tlsmonitor.alerts.service.AlertService;
import com.tlsmonitor.common.dto.ApiResponse;
import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inspection.repository.CertificateDetailsRepository;
import com.tlsmonitor.inspection.repository.TLSScanResultRepository;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.inventory.service.WebsiteService;
import com.tlsmonitor.reporting.service.ExcelReportService;
import com.tlsmonitor.reporting.service.PdfReportService;
import com.tlsmonitor.risk.entity.RiskAssessment;
import com.tlsmonitor.risk.entity.SecurityFinding;
import com.tlsmonitor.risk.repository.RiskAssessmentRepository;
import com.tlsmonitor.risk.repository.SecurityFindingRepository;
import com.tlsmonitor.risk.service.RiskAnalyzer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
public class ReportController {

    private final WebsiteService websiteService;
    private final TLSScanResultRepository scanRepository;
    private final CertificateDetailsRepository certRepository;
    private final RiskAssessmentRepository riskRepository;
    private final SecurityFindingRepository findingRepository;
    private final AlertService alertService;
    private final PdfReportService pdfReportService;
    private final ExcelReportService excelReportService;

    public ReportController(WebsiteService websiteService,
                            TLSScanResultRepository scanRepository,
                            CertificateDetailsRepository certRepository,
                            RiskAssessmentRepository riskRepository,
                            SecurityFindingRepository findingRepository,
                            AlertService alertService,
                            PdfReportService pdfReportService,
                            ExcelReportService excelReportService) {
        this.websiteService = websiteService;
        this.scanRepository = scanRepository;
        this.certRepository = certRepository;
        this.riskRepository = riskRepository;
        this.findingRepository = findingRepository;
        this.alertService = alertService;
        this.pdfReportService = pdfReportService;
        this.excelReportService = excelReportService;
    }

    @GetMapping("/reports/{websiteId}/pdf")
    public ResponseEntity<byte[]> downloadPdfReport(
            @PathVariable Long websiteId,
            @RequestParam(name = "inline", defaultValue = "false") boolean inline) throws Exception {

        Website website = websiteService.getWebsiteById(websiteId);
        TLSScanResult scan = scanRepository.findFirstByWebsiteIdOrderByScannedAtDesc(websiteId).orElse(null);
        CertificateDetails cert = certRepository.findFirstByWebsiteIdOrderByIdDesc(websiteId).orElse(null);
        RiskAssessment risk = riskRepository.findFirstByWebsiteIdOrderByAssessedAtDesc(websiteId).orElse(null);
        List<SecurityFinding> findings = scan != null ? findingRepository.findByScanId(scan.getId()) : List.of();

        byte[] pdfBytes = pdfReportService.generateWebsiteReport(website, scan, cert, risk, findings);

        String disposition = inline ? "inline" : "attachment";

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, disposition + "; filename=\"TLS_Security_Report_" + website.getDomain() + ".pdf\"")
                .contentType(MediaType.APPLICATION_PDF)
                .body(pdfBytes);
    }

    @GetMapping("/reports/excel")
    public ResponseEntity<byte[]> downloadExcelWorkbook() throws Exception {
        List<Website> websites = websiteService.getAllWebsites();
        List<TLSScanResult> scans = scanRepository.findAll();
        List<CertificateDetails> certs = certRepository.findAll();
        List<RiskAssessment> assessments = riskRepository.findAll();
        List<SecurityFinding> findings = findingRepository.findAll();
        List<Alert> alerts = alertService.getAllAlerts();

        byte[] excelBytes = excelReportService.generateWorkbook(websites, scans, certs, assessments, findings, alerts);

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"TLS_Security_Monitoring_Report.xlsx\"")
                .contentType(MediaType.parseMediaType("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))
                .body(excelBytes);
    }

    @GetMapping("/alerts")
    public ResponseEntity<ApiResponse<List<Alert>>> getAlerts() {
        return ResponseEntity.ok(ApiResponse.ok(alertService.getAllAlerts()));
    }

    @PutMapping("/alerts/{id}/acknowledge")
    public ResponseEntity<ApiResponse<Alert>> acknowledgeAlert(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.ok("Alert acknowledged", alertService.acknowledgeAlert(id)));
    }

    @PutMapping("/alerts/{id}/resolve")
    public ResponseEntity<ApiResponse<Alert>> resolveAlert(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.ok("Alert resolved", alertService.resolveAlert(id)));
    }
}
