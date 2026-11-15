package com.tlsmonitor.risk.service;

import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.risk.entity.RiskAssessment;
import com.tlsmonitor.risk.entity.SecurityFinding;
import com.tlsmonitor.risk.repository.RiskAssessmentRepository;
import com.tlsmonitor.risk.repository.SecurityFindingRepository;
import com.tlsmonitor.risk.rules.RiskRule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class RiskAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(RiskAnalyzer.class);

    private final List<RiskRule> riskRules;
    private final RiskScoringService scoringService;
    private final SecurityFindingRepository findingRepository;
    private final RiskAssessmentRepository assessmentRepository;

    public RiskAnalyzer(List<RiskRule> riskRules,
                        RiskScoringService scoringService,
                        SecurityFindingRepository findingRepository,
                        RiskAssessmentRepository assessmentRepository) {
        this.riskRules = riskRules;
        this.scoringService = scoringService;
        this.findingRepository = findingRepository;
        this.assessmentRepository = assessmentRepository;
    }

    public record AnalysisResult(RiskAssessment assessment, List<SecurityFinding> findings) {}

    @Transactional
    public AnalysisResult analyzeAndPersist(TLSScanResult scan, CertificateDetails cert) {
        List<SecurityFinding> findings = new ArrayList<>();

        for (RiskRule rule : riskRules) {
            try {
                List<SecurityFinding> ruleFindings = rule.evaluate(scan, cert);
                if (ruleFindings != null) {
                    findings.addAll(ruleFindings);
                }
            } catch (Exception e) {
                log.error("Error evaluating rule {}: {}", rule.getRuleCode(), e.getMessage());
            }
        }

        int score = scoringService.calculateScore(findings);
        String level = scoringService.determineRiskLevel(score, findings);

        Long scanId = scan.getId() != null ? scan.getId() : 0L;
        Long websiteId = scan.getWebsiteId() != null ? scan.getWebsiteId() : 0L;

        RiskAssessment assessment = new RiskAssessment(scanId, websiteId, score, level, findings.size());
        assessment.setAssessedAt(LocalDateTime.now());
        RiskAssessment savedAssessment = assessmentRepository.save(assessment);

        List<SecurityFinding> savedFindings = new ArrayList<>();
        for (SecurityFinding finding : findings) {
            finding.setScanId(scanId);
            finding.setWebsiteId(websiteId);
            savedFindings.add(findingRepository.save(finding));
        }

        log.info("Risk analysis complete for websiteId {}: score={}, level={}, findings={}",
                websiteId, score, level, findings.size());

        return new AnalysisResult(savedAssessment, savedFindings);
    }

    public Optional<RiskAssessment> getLatestAssessment(Long websiteId) {
        return assessmentRepository.findFirstByWebsiteIdOrderByAssessedAtDesc(websiteId);
    }

    public List<SecurityFinding> getFindingsForScan(Long scanId) {
        return findingRepository.findByScanId(scanId);
    }

    public List<SecurityFinding> getFindingsForWebsite(Long websiteId) {
        return findingRepository.findByWebsiteIdOrderByCreatedAtDesc(websiteId);
    }

    public long countCriticalRisks() {
        return assessmentRepository.countByRiskLevel("CRITICAL");
    }
}
