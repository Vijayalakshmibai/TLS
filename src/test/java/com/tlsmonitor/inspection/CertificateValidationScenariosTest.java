package com.tlsmonitor.inspection;

import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inspection.repository.CertificateDetailsRepository;
import com.tlsmonitor.inspection.repository.TLSScanResultRepository;
import com.tlsmonitor.inspection.service.ScanOrchestratorService;
import com.tlsmonitor.inspection.service.TLSInspectionService;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.inventory.repository.WebsiteRepository;
import com.tlsmonitor.risk.entity.SecurityFinding;
import com.tlsmonitor.testutil.CertificateTestUtils;
import com.tlsmonitor.testutil.TestTlsServer;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import javax.net.ssl.SSLContext;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
public class CertificateValidationScenariosTest {

    @Autowired
    private ScanOrchestratorService scanOrchestratorService;

    @Autowired
    private TLSInspectionService inspectionService;

    @Autowired
    private WebsiteRepository websiteRepository;

    @Autowired
    private TLSScanResultRepository scanResultRepository;

    @Autowired
    private CertificateDetailsRepository certificateDetailsRepository;

    private static SSLContext originalDefaultSslContext;
    private static KeyPair caKeyPair;
    private static X509Certificate caCert;
    private static SSLContext caTrustSslContext;

    @BeforeAll
    static void initCaAndTrust() throws Exception {
        originalDefaultSslContext = SSLContext.getDefault();

        // 1. Generate Root CA for controlled test environment
        caKeyPair = CertificateTestUtils.generateRsaKeyPair();
        caCert = CertificateTestUtils.generateCaCertificate(caKeyPair, "CN=ControlledTestRootCA,O=TLSMonitorTest,C=US");

        // 2. Create TrustStore containing our Root CA and install as default SSLContext
        KeyStore trustStore = CertificateTestUtils.createTrustStore(caCert, "test-ca");
        caTrustSslContext = CertificateTestUtils.createClientTrustSslContext(trustStore);
        SSLContext.setDefault(caTrustSslContext);
    }

    @AfterAll
    static void restoreDefaultSsl() {
        if (originalDefaultSslContext != null) {
            SSLContext.setDefault(originalDefaultSslContext);
        }
    }

    private Website createAndSaveWebsite(String domain, int port) {
        return websiteRepository.findByDomain(domain)
                .map(existing -> {
                    existing.setPort(port);
                    existing.setUrl("https://" + domain + ":" + port);
                    return websiteRepository.save(existing);
                })
                .orElseGet(() -> {
                    Website website = new Website(domain, "https://" + domain + ":" + port, "Scenario Test Website");
                    website.setPort(port);
                    return websiteRepository.save(website);
                });
    }

    @Test
    @DisplayName("TC-01: Valid HTTPS Certificate")
    void testTC01_ValidHttpsCertificate() throws Exception {
        // Arrange: Generate valid leaf cert signed by CA with 127.0.0.1 SAN
        KeyPair serverKeyPair = CertificateTestUtils.generateRsaKeyPair();
        Date notBefore = Date.from(Instant.now().minus(10, ChronoUnit.DAYS));
        Date notAfter = Date.from(Instant.now().plus(90, ChronoUnit.DAYS));
        X509Certificate serverCert = CertificateTestUtils.generateSignedCertificate(
                "CN=127.0.0.1,O=ValidSite Corp,C=US",
                serverKeyPair,
                caCert,
                caKeyPair.getPrivate(),
                notBefore,
                notAfter,
                List.of("localhost"),
                List.of("127.0.0.1")
        );

        KeyStore serverKeyStore = CertificateTestUtils.createKeyStore(
                serverKeyPair.getPrivate(),
                new Certificate[]{serverCert},
                "server",
                "changeit".toCharArray()
        );
        SSLContext serverSslContext = CertificateTestUtils.createServerSslContext(serverKeyStore, "changeit".toCharArray());

        try (TestTlsServer testServer = new TestTlsServer(serverSslContext)) {
            Website website = createAndSaveWebsite("localhost", testServer.getPort());

            // Act: Run full scan pipeline
            ScanOrchestratorService.ScanPipelineResult result = scanOrchestratorService.executeScanPipeline(website.getId());

            // Assert: Scan result & Certificate Details
            assertNotNull(result);
            TLSScanResult scan = result.scanResult();
            CertificateDetails cert = result.certificateDetails();

            assertNotNull(scan, "Scan result should not be null");
            assertNotNull(cert, "Certificate details should be captured");

            // 1. Verify certificate details captured correctly
            assertTrue(cert.getSubject().contains("127.0.0.1") || cert.getSubject().contains("localhost"), "Subject should match");
            assertTrue(cert.getIssuer().contains("ControlledTestRootCA"), "Issuer should match CA");
            assertNotNull(cert.getSerialNumber(), "Serial number should be present");
            assertNotNull(cert.getValidFrom(), "ValidFrom date should be present");
            assertNotNull(cert.getValidUntil(), "ValidUntil date should be present");
            assertTrue(cert.getDaysRemaining() > 60, "Days remaining should be > 60");
            assertFalse(cert.isExpired(), "Certificate should not be expired");
            assertFalse(cert.isSelfSigned(), "Certificate should be CA-signed, not self-signed");
            assertNotNull(cert.getSha256Fingerprint(), "SHA-256 fingerprint should be present");
            assertTrue(cert.getSha256Fingerprint().contains(":"), "Fingerprint should be formatted hex");
            assertTrue(cert.getSubjectAlternativeNames().contains("localhost") || cert.getSubjectAlternativeNames().contains("127.0.0.1"), "SAN should contain localhost or 127.0.0.1");

            // 2. Verify trust and hostname status
            assertTrue(scan.isTrustChainValid(), "Certificate trust chain should be valid");
            assertTrue(scan.isHostnameValid(), "Hostname verification should pass");
            assertEquals("SUCCESS", scan.getConnectionStatus());

            // 3. Confirm scan result and certificate are saved correctly in DB
            assertNotNull(scan.getId(), "Scan result ID should be generated");
            assertNotNull(cert.getId(), "Certificate details ID should be generated");
            assertEquals(scan.getId(), cert.getScanId());

            assertTrue(scanResultRepository.findById(scan.getId()).isPresent());
            assertTrue(certificateDetailsRepository.findById(cert.getId()).isPresent());
        }
    }

    @Test
    @DisplayName("TC-02: Expired Certificate")
    void testTC02_ExpiredCertificate() throws Exception {
        // Arrange: Generate expired certificate signed by CA (expired 15 days ago)
        KeyPair serverKeyPair = CertificateTestUtils.generateRsaKeyPair();
        Date notBefore = Date.from(Instant.now().minus(60, ChronoUnit.DAYS));
        Date notAfter = Date.from(Instant.now().minus(15, ChronoUnit.DAYS));
        X509Certificate serverCert = CertificateTestUtils.generateSignedCertificate(
                "CN=127.0.0.1,O=Expired Corp,C=US",
                serverKeyPair,
                caCert,
                caKeyPair.getPrivate(),
                notBefore,
                notAfter,
                List.of("localhost"),
                List.of("127.0.0.1")
        );

        KeyStore serverKeyStore = CertificateTestUtils.createKeyStore(
                serverKeyPair.getPrivate(),
                new Certificate[]{serverCert},
                "server",
                "changeit".toCharArray()
        );
        SSLContext serverSslContext = CertificateTestUtils.createServerSslContext(serverKeyStore, "changeit".toCharArray());

        try (TestTlsServer testServer = new TestTlsServer(serverSslContext)) {
            Website website = createAndSaveWebsite("localhost", testServer.getPort());

            // Act: Run full scan pipeline
            ScanOrchestratorService.ScanPipelineResult result = scanOrchestratorService.executeScanPipeline(website.getId());

            // Assert: Certificate captured through fallback trust manager even when normal validation fails
            assertNotNull(result);
            TLSScanResult scan = result.scanResult();
            CertificateDetails cert = result.certificateDetails();

            assertNotNull(scan);
            assertNotNull(cert, "Expired certificate should still be captured for security analysis");

            // Verify certificate is marked as expired and untrusted
            assertTrue(cert.isExpired(), "Certificate should be marked as expired");
            assertFalse(scan.isTrustChainValid(), "Expired certificate trust chain must not be marked valid");

            // Verify appropriate security finding and recommendation are generated
            List<SecurityFinding> findings = result.findings();
            assertFalse(findings.isEmpty(), "Security findings should be generated for expired certificate");

            boolean hasExpiredFinding = findings.stream().anyMatch(f ->
                    "EXP_EXPIRED".equals(f.getRuleCode()) || f.getTitle().toLowerCase().contains("expired"));
            assertTrue(hasExpiredFinding, "Should generate EXP_EXPIRED security finding");

            SecurityFinding expiredFinding = findings.stream()
                    .filter(f -> "EXP_EXPIRED".equals(f.getRuleCode()) || f.getTitle().toLowerCase().contains("expired"))
                    .findFirst().orElseThrow();
            assertNotNull(expiredFinding.getRecommendation(), "Recommendation must be provided");
            assertFalse(expiredFinding.getRecommendation().isBlank(), "Recommendation must not be empty");
        }
    }

    @Test
    @DisplayName("TC-03: Self-Signed Certificate")
    void testTC03_SelfSignedCertificate() throws Exception {
        // Arrange: Generate untrusted self-signed certificate
        KeyPair serverKeyPair = CertificateTestUtils.generateRsaKeyPair();
        Date notBefore = Date.from(Instant.now().minus(5, ChronoUnit.DAYS));
        Date notAfter = Date.from(Instant.now().plus(60, ChronoUnit.DAYS));
        X509Certificate selfSignedCert = CertificateTestUtils.generateSelfSignedCertificate(
                "CN=127.0.0.1,O=SelfSignedOrg,C=US",
                serverKeyPair,
                notBefore,
                notAfter,
                List.of("127.0.0.1")
        );

        KeyStore serverKeyStore = CertificateTestUtils.createKeyStore(
                serverKeyPair.getPrivate(),
                new Certificate[]{selfSignedCert},
                "server",
                "changeit".toCharArray()
        );
        SSLContext serverSslContext = CertificateTestUtils.createServerSslContext(serverKeyStore, "changeit".toCharArray());

        try (TestTlsServer testServer = new TestTlsServer(serverSslContext)) {
            Website website = createAndSaveWebsite("127.0.0.1", testServer.getPort());

            // Act
            ScanOrchestratorService.ScanPipelineResult result = scanOrchestratorService.executeScanPipeline(website.getId());

            // Assert
            assertNotNull(result);
            TLSScanResult scan = result.scanResult();
            CertificateDetails cert = result.certificateDetails();

            assertNotNull(cert, "Self-signed certificate must be captured");
            assertTrue(cert.isSelfSigned(), "Certificate should be identified as self-signed");
            assertFalse(scan.isTrustChainValid(), "Self-signed certificate must NOT be marked as trusted");

            // Verify risk engine generates finding for self-signed certificate
            List<SecurityFinding> findings = result.findings();
            boolean hasSelfSignedFinding = findings.stream().anyMatch(f ->
                    "TRUST_SELF_SIGNED".equals(f.getRuleCode()) || f.getTitle().toLowerCase().contains("self-signed"));
            assertTrue(hasSelfSignedFinding, "Risk engine must generate finding for self-signed certificate");

            SecurityFinding finding = findings.stream()
                    .filter(f -> "TRUST_SELF_SIGNED".equals(f.getRuleCode()) || f.getTitle().toLowerCase().contains("self-signed"))
                    .findFirst().orElseThrow();
            assertEquals("CRITICAL", finding.getSeverity());
            assertNotNull(finding.getRecommendation());
        }
    }

    @Test
    @DisplayName("TC-04: Hostname Mismatch")
    void testTC04_HostnameMismatch() throws Exception {
        // Arrange: Certificate is issued for "unrelated.example.com", NOT 127.0.0.1
        KeyPair serverKeyPair = CertificateTestUtils.generateRsaKeyPair();
        Date notBefore = Date.from(Instant.now().minus(5, ChronoUnit.DAYS));
        Date notAfter = Date.from(Instant.now().plus(60, ChronoUnit.DAYS));
        X509Certificate serverCert = CertificateTestUtils.generateSignedCertificate(
                "CN=unrelated.example.com,O=Unrelated Org,C=US",
                serverKeyPair,
                caCert,
                caKeyPair.getPrivate(),
                notBefore,
                notAfter,
                List.of("unrelated.example.com"),
                Collections.emptyList()
        );

        KeyStore serverKeyStore = CertificateTestUtils.createKeyStore(
                serverKeyPair.getPrivate(),
                new Certificate[]{serverCert},
                "server",
                "changeit".toCharArray()
        );
        SSLContext serverSslContext = CertificateTestUtils.createServerSslContext(serverKeyStore, "changeit".toCharArray());

        try (TestTlsServer testServer = new TestTlsServer(serverSslContext)) {
            // Target domain is 127.0.0.1, which does NOT match unrelated.example.com
            Website website = createAndSaveWebsite("127.0.0.1", testServer.getPort());

            // Act
            ScanOrchestratorService.ScanPipelineResult result = scanOrchestratorService.executeScanPipeline(website.getId());

            // Assert
            assertNotNull(result);
            TLSScanResult scan = result.scanResult();
            CertificateDetails cert = result.certificateDetails();

            // Verify hostname validation detected the mismatch
            assertFalse(scan.isHostnameValid(), "Hostname validation must detect mismatch");

            // Ensure certificate capture does not hide the validation failure
            assertNotNull(cert, "Certificate must still be captured despite hostname mismatch");
            assertTrue(cert.getSubject().contains("unrelated.example.com"));

            // Confirm that scan records the mismatch as a security finding
            List<SecurityFinding> findings = result.findings();
            boolean hasMismatchFinding = findings.stream().anyMatch(f ->
                    "HOST_MISMATCH".equals(f.getRuleCode()) || f.getTitle().toLowerCase().contains("mismatch"));
            assertTrue(hasMismatchFinding, "Finding must be generated for hostname mismatch");
        }
    }

    @Test
    @DisplayName("TC-05: Not-Yet-Valid Certificate")
    void testTC05_NotYetValidCertificate() throws Exception {
        // Arrange: Validity period starts 15 days in the future
        KeyPair serverKeyPair = CertificateTestUtils.generateRsaKeyPair();
        Date notBefore = Date.from(Instant.now().plus(15, ChronoUnit.DAYS));
        Date notAfter = Date.from(Instant.now().plus(365, ChronoUnit.DAYS));
        X509Certificate serverCert = CertificateTestUtils.generateSignedCertificate(
                "CN=127.0.0.1,O=Future Corp,C=US",
                serverKeyPair,
                caCert,
                caKeyPair.getPrivate(),
                notBefore,
                notAfter,
                List.of("localhost"),
                List.of("127.0.0.1")
        );

        KeyStore serverKeyStore = CertificateTestUtils.createKeyStore(
                serverKeyPair.getPrivate(),
                new Certificate[]{serverCert},
                "server",
                "changeit".toCharArray()
        );
        SSLContext serverSslContext = CertificateTestUtils.createServerSslContext(serverKeyStore, "changeit".toCharArray());

        try (TestTlsServer testServer = new TestTlsServer(serverSslContext)) {
            Website website = createAndSaveWebsite("127.0.0.1", testServer.getPort());

            // Act
            ScanOrchestratorService.ScanPipelineResult result = scanOrchestratorService.executeScanPipeline(website.getId());

            // Assert
            assertNotNull(result);
            TLSScanResult scan = result.scanResult();
            CertificateDetails cert = result.certificateDetails();

            assertNotNull(cert, "Not-yet-valid certificate must be captured");

            // 1. Verify application identifies it as not yet valid
            assertTrue(cert.isNotYetValid(), "Certificate must be identified as not yet valid");

            // 2. Confirm that it is not incorrectly classified as a valid certificate
            assertFalse(scan.isTrustChainValid(), "Not-yet-valid certificate must not be marked trusted");

            // 3. Check the generated finding and recommendation
            List<SecurityFinding> findings = result.findings();
            boolean hasNotYetValidFinding = findings.stream().anyMatch(f ->
                    "EXP_NOT_YET_VALID".equals(f.getRuleCode()) || f.getTitle().toLowerCase().contains("not yet valid"));
            assertTrue(hasNotYetValidFinding, "Finding must be generated for not-yet-valid certificate");

            SecurityFinding finding = findings.stream()
                    .filter(f -> "EXP_NOT_YET_VALID".equals(f.getRuleCode()) || f.getTitle().toLowerCase().contains("not yet valid"))
                    .findFirst().orElseThrow();
            assertNotNull(finding.getRecommendation(), "Recommendation should be present");
            assertFalse(finding.getRecommendation().isBlank(), "Recommendation should not be blank");
        }
    }
}
