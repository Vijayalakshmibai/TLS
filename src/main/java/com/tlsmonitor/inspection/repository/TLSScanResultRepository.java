package com.tlsmonitor.inspection.repository;

import com.tlsmonitor.inspection.entity.TLSScanResult;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TLSScanResultRepository extends JpaRepository<TLSScanResult, Long> {
    List<TLSScanResult> findByWebsiteIdOrderByScannedAtDesc(Long websiteId);
    Optional<TLSScanResult> findFirstByWebsiteIdOrderByScannedAtDesc(Long websiteId);
    long countByConnectionStatus(String status);
}
