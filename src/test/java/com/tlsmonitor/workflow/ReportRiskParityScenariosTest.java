package com.tlsmonitor.workflow;

import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inspection.repository.CertificateDetailsRepository;
import com.tlsmonitor.inspection.repository.TLSScanResultRepository;
import com.tlsmonitor.inspection.tls.TLSInspector;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.inventory.repository.WebsiteRepository;
import com.tlsmonitor.reporting.controller.ReportController;
import com.tlsmonitor.risk.entity.RiskAssessment;
import com.tlsmonitor.risk.entity.SecurityFinding;
import com.tlsmonitor.risk.repository.RiskAssessmentRepository;
import com.tlsmonitor.risk.repository.SecurityFindingRepository;
import com.tlsmonitor.risk.service.RiskReportResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Step 1 verification: the Risk Analysis page and the PDF report must render the findings of the
 * same latest scan, with score/severity/count derived from that same finding set — never the
 * website's entire scan history, and never a stale persisted assessment.
 */
@SpringBootTest
@ActiveProfiles("test")
@DisplayName("Risk page <-> PDF report parity (Step 1)")
public class ReportRiskParityScenariosTest {

    @Autowired
    private WebsiteRepository websiteRepository;

    @Autowired
    private TLSScanResultRepository scanResultRepository;

    @Autowired
    private CertificateDetailsRepository certificateDetailsRepository;

    @Autowired
    private RiskAssessmentRepository riskAssessmentRepository;

    @Autowired
    private SecurityFindingRepository securityFindingRepository;

    @Autowired
    private RiskReportResolver riskReportResolver;

    @Autowired
    private ReportController reportController;

    @MockitoBean
    private TLSInspector tlsInspector;

    @BeforeEach
    void cleanDatabase() {
        securityFindingRepository.deleteAll();
        riskAssessmentRepository.deleteAll();
        certificateDetailsRepository.deleteAll();
        scanResultRepository.deleteAll();
        websiteRepository.deleteAll();
    }

    private Website registerWebsite(String domain) {
        Website site = new Website(domain, "https://" + domain, "Parity Test Target");
        site.setStatus("ACTIVE");
        site.setContactEmail("ops@" + domain);
        site.setCreatedAt(LocalDateTime.now());
        site.setUpdatedAt(LocalDateTime.now());
        return websiteRepository.save(site);
    }

    private TLSScanResult saveScan(Website site, LocalDateTime scannedAt) {
        TLSScanResult scan = new TLSScanResult();
        scan.setWebsiteId(site.getId());
        scan.setDomain(site.getDomain());
        scan.setPort(site.getPort());
        scan.setConnectionStatus("SUCCESS");
        scan.setTlsVersion("TLSv1.2");
        scan.setCipherSuite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        scan.setHostnameValid(false);       // force at least one finding
        scan.setTrustChainValid(false);     // force at least one finding
        scan.setSupportedProtocols("TLSv1.0, TLSv1.2");
        scan.setWeakProtocolDetected(true);
        scan.setResponseTimeMs(50);
        scan.setResolvedIp("93.184.216.34");
        scan.setScannedAt(scannedAt);
        return scanResultRepository.save(scan);
    }

    private CertificateDetails saveCertificate(Website site, Long scanId, LocalDateTime validUntil) {
        CertificateDetails cert = new CertificateDetails();
        cert.setWebsiteId(site.getId());
        cert.setScanId(scanId);
        cert.setSubject("CN=" + site.getDomain() + ",O=ParityCorp,C=US");
        cert.setIssuer("CN=UntrustedCA,O=BadCorp,C=US");
        cert.setSerialNumber("SN-PARITY-001");
        cert.setSignatureAlgorithm("SHA256withRSA");
        cert.setPublicKeyAlgorithm("RSA");
        cert.setKeySize(2048);
        cert.setDaysRemaining(-3);          // force EXP_EXPIRED-style finding
        cert.setExpired(true);
        cert.setSelfSigned(true);
        cert.setValidFrom(LocalDateTime.now().minusDays(90));
        cert.setValidUntil(validUntil);
        cert.setSha256Fingerprint("AA:BB:CC:DD");
        return certificateDetailsRepository.save(cert);
    }

    @Test
    @DisplayName("Resolve on fresh scan persists assessment + findings scoped to that scan; repeat resolve does not duplicate")
    void freshScanResolutionIsScanScopedAndIdempotent() {
        Website site = registerWebsite("parity-fresh.example.com");
        TLSScanResult scan = saveScan(site, LocalDateTime.now().minusHours(1));
        saveCertificate(site, scan.getId(), LocalDateTime.now().minusDays(3));

        Optional<RiskReportResolver.ResolvedRisk> resolved = riskReportResolver.resolve(site.getId());
        assertTrue(resolved.isPresent(), "A scan exists, so resolution must succeed");
        RiskReportResolver.ResolvedRisk r = resolved.get();

        assertEquals(scan.getId(), r.scan().getId());
        assertEquals(scan.getId(), r.assessment().getScanId(), "Assessment must belong to the latest scan");
        assertFalse(r.findings().isEmpty(), "Findings must be produced for a bad scan");
        for (SecurityFinding f : r.findings()) {
            assertEquals(scan.getId(), f.getScanId(), "Every finding must reference the resolved scan only");
            assertEquals(site.getId(), f.getWebsiteId());
        }
        assertEquals(r.findings().size(), r.assessment().getFindingsCount(),
                "Assessment findings count must equal the scan-scoped findings size (page 'Total Issues')");

        long assessmentsBefore = riskAssessmentRepository.count();
        long findingsBefore = securityFindingRepository.count();
        Optional<RiskReportResolver.ResolvedRisk> again = riskReportResolver.resolve(site.getId());
        assertTrue(again.isPresent());
        assertEquals(r.assessment().getId(), again.get().assessment().getId(),
                "Second resolve must reuse the assessment that covers the latest scan");
        assertEquals(assessmentsBefore, riskAssessmentRepository.count(), "No duplicate assessment may be persisted");
        assertEquals(findingsBefore, securityFindingRepository.count(), "No duplicate findings may be persisted");
        assertEquals(again.get().findings().size(), again.get().assessment().getFindingsCount());
    }

    @Test
    @DisplayName("Stale persisted assessment is discarded and recomputed for the latest scan (no lifetime finding leakage)")
    void staleAssessmentIsRecomputedAndFindingsAreScanScoped() {
        Website site = registerWebsite("parity-stale.example.com");

        // Older scan + its assessment/findings
        TLSScanResult oldScan = saveScan(site, LocalDateTime.now().minusDays(2));
        saveCertificate(site, oldScan.getId(), LocalDateTime.now().minusDays(3));
        Optional<RiskReportResolver.ResolvedRisk> first = riskReportResolver.resolve(site.getId());
        assertTrue(first.isPresent());
        RiskAssessment staleAssessment = first.get().assessment();
        assertEquals(oldScan.getId(), staleAssessment.getScanId());
        int oldFindings = first.get().findings().size();
        assertTrue(oldFindings > 0);

        // Newer scan appears afterwards -> persisted assessment is now stale
        TLSScanResult newScan = saveScan(site, LocalDateTime.now().minusMinutes(30));
        saveCertificate(site, newScan.getId(), LocalDateTime.now().minusDays(1));

        Optional<RiskReportResolver.ResolvedRisk> second = riskReportResolver.resolve(site.getId());
        assertTrue(second.isPresent());
        RiskReportResolver.ResolvedRisk r = second.get();

        assertEquals(newScan.getId(), r.scan().getId(), "Resolution must target the latest scan");
        assertEquals(newScan.getId(), r.assessment().getScanId(), "Stale assessment must be recomputed for the new scan");
        assertNotEquals(staleAssessment.getId(), r.assessment().getId(), "A fresh assessment must be persisted");

        for (SecurityFinding f : r.findings()) {
            assertEquals(newScan.getId(), f.getScanId(), "Findings of the new assessment must not leak in from older scans");
        }

        long lifetimeFindings = securityFindingRepository.findByWebsiteIdOrderByCreatedAtDesc(site.getId()).size();
        assertTrue(lifetimeFindings > r.findings().size(),
                "Lifetime finding count (" + lifetimeFindings + ") must exceed the scan-scoped count ("
                        + r.findings().size() + ") — otherwise this test proves nothing");
        assertEquals(r.findings().size(), r.assessment().getFindingsCount());
    }

    @Test
    @DisplayName("PDF endpoint serves a report built from the same resolved assessment and findings (page parity)")
    void pdfEndpointUsesSameResolutionAsPage() throws Exception {
        Website site = registerWebsite("parity-pdf.example.com");
        TLSScanResult scan = saveScan(site, LocalDateTime.now().minusHours(2));
        saveCertificate(site, scan.getId(), LocalDateTime.now().minusDays(2));

        Optional<RiskReportResolver.ResolvedRisk> resolved = riskReportResolver.resolve(site.getId());
        assertTrue(resolved.isPresent());
        String expectedAssessmentId = String.valueOf(resolved.get().assessment().getId());
        int expectedFindings = resolved.get().findings().size();

        ResponseEntity<byte[]> response = reportController.downloadPdfReport(site.getId(), false);

        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().length > 500, "PDF body must be a real generated document");
        assertEquals("application/pdf", response.getHeaders().getContentType().toString());

        // The PDF endpoint must not have persisted a *new* assessment for the same scan —
        // it reuses exactly what the page would display.
        List<RiskAssessment> all = riskAssessmentRepository.findAll();
        assertEquals(1, all.size(), "PDF generation after resolution must not create a duplicate assessment");
        assertEquals(expectedAssessmentId, String.valueOf(all.get(0).getId()));
        assertEquals(expectedFindings, all.get(0).getFindingsCount());
    }
}
