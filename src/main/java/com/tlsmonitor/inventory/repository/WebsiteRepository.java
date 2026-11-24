package com.tlsmonitor.inventory.repository;

import com.tlsmonitor.inventory.entity.Website;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface WebsiteRepository extends JpaRepository<Website, Long> {
    Optional<Website> findByDomain(String domain);
    boolean existsByDomain(String domain);
    boolean existsByDomainIgnoreCase(String domain);
    List<Website> findByStatus(String status);
}
