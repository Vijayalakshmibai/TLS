package com.tlsmonitor.inspection.repository;

import com.tlsmonitor.inspection.entity.CertificateDetails;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CertificateDetailsRepository extends JpaRepository<CertificateDetails, Long> {
    Optional<CertificateDetails> findByScanId(Long scanId);
    Optional<CertificateDetails> findFirstByWebsiteIdOrderByIdDesc(Long websiteId);

    @Query("SELECT COUNT(c) FROM CertificateDetails c WHERE c.daysRemaining <= :days AND c.expired = false")
    long countExpiringSoon(@Param("days") long days);

    @Query("SELECT COUNT(c) FROM CertificateDetails c WHERE c.expired = true")
    long countExpired();
}
