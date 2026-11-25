package com.tlsmonitor.risk.service;

import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inspection.service.TLSInspectionService;
import com.tlsmonitor.risk.entity.RiskAssessment;
import com.tlsmonitor.risk.entity.SecurityFinding;

import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;

/**
 * Single source of truth for "which risk assessment and findings describe the current state of a
 * website". Used identically by the Risk Analysis page and the PDF/Excel report endpoints so the
 * score, severity, issue count and recommendations always describe the same scan.
 *
 * Resolution rules:
 *   1. No scan exists            -> empty (page shows the empty state; report endpoints render the
 *                                  report without risk data).
 *   2. Latest assessment covers  -> reuse it (no recomputation, no duplicate findings).
 *      the latest scan (same scanId)
 *   3. Assessment is stale       -> recompute & persist a fresh assessment + findings for the
 *      (an assessment exists but    latest scan, instead of reusing the stale row.
 *      its scanId != the latest scan's id)
 *
 * Findings are always those persisted for the resolved assessment's scan — never the website's
 * entire history.
 */
@Service
public class RiskReportResolver {

    private final TLSInspectionService inspectionService;
    private final RiskAnalyzer riskAnalyzer;

    public RiskReportResolver(TLSInspectionService inspectionService, RiskAnalyzer riskAnalyzer) {
        this.inspectionService = inspectionService;
        this.riskAnalyzer = riskAnalyzer;
    }

    /** Immutable bundle passed to views and report generators. */
    public record ResolvedRisk(TLSScanResult scan,
                               CertificateDetails certificate,
                               RiskAssessment assessment,
                               List<SecurityFinding> findings) {
    }

    public Optional<ResolvedRisk> resolve(Long websiteId) {
        Optional<TLSScanResult> scanOpt = inspectionService.getLatestScan(websiteId);
        if (scanOpt.isEmpty()) {
            return Optional.empty();
        }
        TLSScanResult scan = scanOpt.get();
        CertificateDetails cert = inspectionService.getCertificateByScanId(scan.getId()).orElse(null);

        Optional<RiskAssessment> assessment = riskAnalyzer.getLatestAssessment(websiteId);
        if (assessment.isEmpty() || !assessment.get().getScanId().equals(scan.getId())) {
            // No assessment, or the persisted assessment belongs to an older scan -> recompute
            // and persist a fresh assessment + findings for the latest scan.
            RiskAnalyzer.AnalysisResult result = riskAnalyzer.analyzeAndPersist(scan, cert);
            assessment = Optional.of(result.assessment());
        }

        RiskAssessment resolved = assessment.get();
        List<SecurityFinding> findings = riskAnalyzer.getFindingsForScan(resolved.getScanId());
        return Optional.of(new ResolvedRisk(scan, cert, resolved, findings));
    }
}
