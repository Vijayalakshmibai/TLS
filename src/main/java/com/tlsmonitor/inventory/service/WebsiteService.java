package com.tlsmonitor.inventory.service;

import com.tlsmonitor.common.exception.InvalidDomainException;
import com.tlsmonitor.common.exception.ResourceNotFoundException;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.inventory.repository.WebsiteRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class WebsiteService {

    private static final Logger log = LoggerFactory.getLogger(WebsiteService.class);

    private final WebsiteRepository websiteRepository;
    private final WebsiteValidationService validationService;

    public WebsiteService(WebsiteRepository websiteRepository, WebsiteValidationService validationService) {
        this.websiteRepository = websiteRepository;
        this.validationService = validationService;
    }

    @Transactional
    public Website addWebsite(Website website) {
        if (website == null || website.getDomain() == null) {
            throw new InvalidDomainException("Website domain is required.");
        }

        WebsiteValidationService.NormalizedTarget target = validationService.normalizeAndValidate(website.getDomain());

        if (websiteRepository.existsByDomain(target.domain())) {
            throw new IllegalArgumentException("Website with domain '" + target.domain() + "' is already registered in inventory.");
        }

        website.setDomain(target.domain());
        website.setPort(target.port());
        website.setUrl(target.normalizedUrl());
        if (website.getStatus() == null || website.getStatus().trim().isEmpty()) {
            website.setStatus("ACTIVE");
        }
        website.setCreatedAt(LocalDateTime.now());
        website.setUpdatedAt(LocalDateTime.now());

        log.info("Registered new website: domain={}, url={}", website.getDomain(), website.getUrl());
        return websiteRepository.save(website);
    }

    public List<Website> getAllWebsites() {
        return websiteRepository.findAll();
    }

    public Website getWebsiteById(Long id) {
        return websiteRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Website not found with ID: " + id));
    }

    @Transactional
    public Website updateWebsite(Long id, Website updated) {
        Website existing = getWebsiteById(id);

        if (updated.getDescription() != null) {
            existing.setDescription(updated.getDescription());
        }
        if (updated.getContactEmail() != null) {
            existing.setContactEmail(updated.getContactEmail());
        }
        if (updated.getStatus() != null) {
            existing.setStatus(updated.getStatus());
        }
        if (updated.getPort() > 0 && updated.getPort() <= 65535) {
            existing.setPort(updated.getPort());
        }
        existing.setUpdatedAt(LocalDateTime.now());

        log.info("Updated website ID {}: domain={}", id, existing.getDomain());
        return websiteRepository.save(existing);
    }

    @Transactional
    public void deleteWebsite(Long id) {
        Website website = getWebsiteById(id);
        websiteRepository.delete(website);
        log.info("Deleted website ID {}: domain={}", id, website.getDomain());
    }

    @Transactional
    public void recordScanCompleted(Long id) {
        websiteRepository.findById(id).ifPresent(site -> {
            site.setLastScannedAt(LocalDateTime.now());
            websiteRepository.save(site);
        });
    }

    public long countTotalWebsites() {
        return websiteRepository.count();
    }

    public long countActiveWebsites() {
        return websiteRepository.findByStatus("ACTIVE").size();
    }
}
