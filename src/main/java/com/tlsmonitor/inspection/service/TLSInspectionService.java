package com.tlsmonitor.inspection.service;

import com.tlsmonitor.common.exception.ResourceNotFoundException;
import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inspection.repository.CertificateDetailsRepository;
import com.tlsmonitor.inspection.repository.TLSScanResultRepository;
import com.tlsmonitor.inspection.tls.TLSInspector;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.inventory.service.WebsiteService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
public class TLSInspectionService {

    private static final Logger log = LoggerFactory.getLogger(TLSInspectionService.class);

    private final TLSInspector tlsInspector;
    private final TLSScanResultRepository scanResultRepository;
    private final CertificateDetailsRepository certificateDetailsRepository;
    private final WebsiteService websiteService;

    public TLSInspectionService(TLSInspector tlsInspector,
                                TLSScanResultRepository scanResultRepository,
                                CertificateDetailsRepository certificateDetailsRepository,
                                WebsiteService websiteService) {
        this.tlsInspector = tlsInspector;
        this.scanResultRepository = scanResultRepository;
        this.certificateDetailsRepository = certificateDetailsRepository;
        this.websiteService = websiteService;
    }

    @Transactional
    public TLSInspector.InspectionOutcome performScan(Long websiteId) {
        Website website = websiteService.getWebsiteById(websiteId);
        log.info("Initiating TLS inspection for website: domain={}, port={}", website.getDomain(), website.getPort());

        TLSInspector.InspectionOutcome outcome = tlsInspector.inspect(website.getId(), website.getDomain(), website.getPort());

        TLSScanResult savedScan = scanResultRepository.save(outcome.scanResult());
        CertificateDetails savedCert = null;

        if (outcome.certificateDetails() != null) {
            outcome.certificateDetails().setScanId(savedScan.getId());
            savedCert = certificateDetailsRepository.save(outcome.certificateDetails());
        }

        websiteService.recordScanCompleted(websiteId);
        log.info("Completed TLS inspection for {}: status={}, tls={}, cipher={}",
                website.getDomain(), savedScan.getConnectionStatus(), savedScan.getTlsVersion(), savedScan.getCipherSuite());

        return new TLSInspector.InspectionOutcome(savedScan, savedCert);
    }

    public List<TLSScanResult> getScanHistory(Long websiteId) {
        return scanResultRepository.findByWebsiteIdOrderByScannedAtDesc(websiteId);
    }

    public Optional<TLSScanResult> getLatestScan(Long websiteId) {
        return scanResultRepository.findFirstByWebsiteIdOrderByScannedAtDesc(websiteId);
    }

    public Optional<CertificateDetails> getLatestCertificate(Long websiteId) {
        return certificateDetailsRepository.findFirstByWebsiteIdOrderByIdDesc(websiteId);
    }

    public Optional<CertificateDetails> getCertificateByScanId(Long scanId) {
        return certificateDetailsRepository.findByScanId(scanId);
    }

    public long countSuccessfulScans() {
        return scanResultRepository.countByConnectionStatus("SUCCESS");
    }
}
