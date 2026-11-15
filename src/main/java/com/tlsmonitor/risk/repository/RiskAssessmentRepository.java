package com.tlsmonitor.risk.repository;

import com.tlsmonitor.risk.entity.RiskAssessment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RiskAssessmentRepository extends JpaRepository<RiskAssessment, Long> {
    Optional<RiskAssessment> findByScanId(Long scanId);
    Optional<RiskAssessment> findFirstByWebsiteIdOrderByAssessedAtDesc(Long websiteId);
    long countByRiskLevel(String riskLevel);
}
