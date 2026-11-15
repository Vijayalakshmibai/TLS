package com.tlsmonitor.risk.repository;

import com.tlsmonitor.risk.entity.SecurityFinding;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SecurityFindingRepository extends JpaRepository<SecurityFinding, Long> {
    List<SecurityFinding> findByScanId(Long scanId);
    List<SecurityFinding> findByWebsiteIdOrderByCreatedAtDesc(Long websiteId);
    long countBySeverity(String severity);
}
