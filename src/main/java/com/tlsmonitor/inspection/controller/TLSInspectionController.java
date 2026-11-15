package com.tlsmonitor.inspection.controller;

import com.tlsmonitor.common.dto.ApiResponse;
import com.tlsmonitor.common.exception.ResourceNotFoundException;
import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inspection.service.ScanOrchestratorService;
import com.tlsmonitor.inspection.service.TLSInspectionService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
public class TLSInspectionController {

    private final TLSInspectionService inspectionService;
    private final ScanOrchestratorService scanOrchestratorService;

    public TLSInspectionController(TLSInspectionService inspectionService,
                                   ScanOrchestratorService scanOrchestratorService) {
        this.inspectionService = inspectionService;
        this.scanOrchestratorService = scanOrchestratorService;
    }

    @PostMapping("/scans/{websiteId}")
    public ResponseEntity<ApiResponse<TLSScanResult>> triggerScan(@PathVariable Long websiteId) {
        ScanOrchestratorService.ScanPipelineResult result = scanOrchestratorService.executeScanPipeline(websiteId);
        return ResponseEntity.ok(ApiResponse.ok("TLS inspection and risk scoring completed", result.scanResult()));
    }

    @GetMapping("/scans/{websiteId}")
    public ResponseEntity<ApiResponse<List<TLSScanResult>>> getScanHistory(@PathVariable Long websiteId) {
        List<TLSScanResult> history = inspectionService.getScanHistory(websiteId);
        return ResponseEntity.ok(ApiResponse.ok(history));
    }

    @GetMapping("/certificates/{websiteId}")
    public ResponseEntity<ApiResponse<CertificateDetails>> getLatestCertificate(@PathVariable Long websiteId) {
        CertificateDetails details = inspectionService.getLatestCertificate(websiteId)
                .orElseThrow(() -> new ResourceNotFoundException("No certificate record found for website ID: " + websiteId));
        return ResponseEntity.ok(ApiResponse.ok(details));
    }
}
