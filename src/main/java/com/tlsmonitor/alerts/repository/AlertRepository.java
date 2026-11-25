package com.tlsmonitor.alerts.repository;

import com.tlsmonitor.alerts.entity.Alert;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AlertRepository extends JpaRepository<Alert, Long> {
    List<Alert> findByWebsiteIdOrderByCreatedAtDesc(Long websiteId);
    List<Alert> findByWebsiteIdAndStatusNot(Long websiteId, String status);
    List<Alert> findByStatusNot(String status);
    List<Alert> findAllByOrderByCreatedAtDesc();
    List<Alert> findByStatusOrderByCreatedAtDesc(String status);
    List<Alert> findByWebsiteIdAndAlertTypeAndStatusNot(Long websiteId, String alertType, String status);
    boolean existsByWebsiteIdAndAlertTypeAndStatus(Long websiteId, String alertType, String status);
    long countByStatus(String status);
}
