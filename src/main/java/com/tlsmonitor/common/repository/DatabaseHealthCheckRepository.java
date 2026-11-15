package com.tlsmonitor.common.repository;

import com.tlsmonitor.common.entity.DatabaseHealthCheck;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface DatabaseHealthCheckRepository extends JpaRepository<DatabaseHealthCheck, Long> {
}
