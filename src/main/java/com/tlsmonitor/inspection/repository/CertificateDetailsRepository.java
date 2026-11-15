package com.tlsmonitor.inspection.repository;

import com.tlsmonitor.inspection.entity.CertificateDetails;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CertificateDetailsRepository extends JpaRepository<CertificateDetails, Long> {
    Optional<CertificateDetails> findByScanId(Long scanId);
    Optional<CertificateDetails> findFirstByWebsiteIdOrderByIdDesc(Long websiteId);
}
