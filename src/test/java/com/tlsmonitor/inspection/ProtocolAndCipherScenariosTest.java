package com.tlsmonitor.inspection;

import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inspection.tls.CertificateExtractor;
import com.tlsmonitor.inspection.tls.TLSConfigurationScanner;
import com.tlsmonitor.inspection.tls.TLSInspector;
import com.tlsmonitor.risk.entity.SecurityFinding;
import com.tlsmonitor.risk.rules.WeakCipherRule;
import com.tlsmonitor.risk.rules.WeakProtocolRule;
import com.tlsmonitor.testutil.CertificateTestUtils;
import com.tlsmonitor.testutil.TestTlsServer;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.net.ssl.SSLContext;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Functional test suite for TLS Protocol Detection and Cipher-Suite Security Analysis (TC-11 to TC-15).
 * Tests protocol detection, classification, weak cipher detection, and JSSE runtime environment capabilities.
 */
public class ProtocolAndCipherScenariosTest {

    private static KeyPair caKeyPair;
    private static X509Certificate caCert;
    private static KeyPair serverKeyPair;
    private static X509Certificate serverCert;
    private static SSLContext serverSslContext;

    private TLSConfigurationScanner configurationScanner;
    private CertificateExtractor certificateExtractor;
    private TLSInspector tlsInspector;
    private WeakProtocolRule weakProtocolRule;
    private WeakCipherRule weakCipherRule;

    @BeforeAll
    static void initCrypto() throws Exception {
        caKeyPair = CertificateTestUtils.generateRsaKeyPair();
        caCert = CertificateTestUtils.generateCaCertificate(caKeyPair, "CN=ProtocolTestCA,O=TLSMonitor,C=US");

        serverKeyPair = CertificateTestUtils.generateRsaKeyPair();
        Instant now = Instant.now();
        Date notBefore = Date.from(now.minus(1, ChronoUnit.DAYS));
        Date notAfter = Date.from(now.plus(365, ChronoUnit.DAYS));

        serverCert = CertificateTestUtils.generateSignedCertificate(
                "CN=127.0.0.1",
                serverKeyPair,
                caCert,
                caKeyPair.getPrivate(),
                notBefore,
                notAfter,
                List.of("127.0.0.1", "localhost"),
                List.of("127.0.0.1")
        );

        var keyStore = CertificateTestUtils.createKeyStore(
                serverKeyPair.getPrivate(),
                new Certificate[]{serverCert},
                "server",
                "password".toCharArray()
        );
        serverSslContext = CertificateTestUtils.createServerSslContext(keyStore, "password".toCharArray());
    }

    @BeforeEach
    void setUp() {
        configurationScanner = new TLSConfigurationScanner();
        certificateExtractor = new CertificateExtractor();
        tlsInspector = new TLSInspector(certificateExtractor, configurationScanner);
        weakProtocolRule = new WeakProtocolRule();
        weakCipherRule = new WeakCipherRule();
    }

    private static boolean isProtocolDisabledInJvm(String protocol) {
        try {
            String disabled = java.security.Security.getProperty("jdk.tls.disabledAlgorithms");
            if (disabled != null) {
                for (String part : disabled.split(",")) {
                    if (part.trim().equalsIgnoreCase(protocol)) {
                        return true;
                    }
                }
            }
        } catch (Exception ignored) {}
        return false;
    }

    // =========================================================================
    // TC-11: TLS 1.0 Detection
    // =========================================================================
    @Test
    @DisplayName("TC-11: TLS 1.0 support detection and outdated classification finding")
    void testTC11_Tls10DetectionAndClassification() {
        // Verify protocol is recognized as outdated by the scanner
        assertTrue(configurationScanner.isOutdatedProtocol("TLSv1"), "TLSv1 must be recognized as outdated");
        assertTrue(configurationScanner.isOutdatedProtocol("TLSv1.0"), "TLSv1.0 must be recognized as outdated");

        // Verify security finding generation when TLS 1.0 is detected
        TLSScanResult scan = new TLSScanResult();
        scan.setId(101L);
        scan.setWebsiteId(1L);
        scan.setTlsVersion("TLSv1.0");
        scan.setSupportedProtocols("TLSv1.0, TLSv1.2");
        scan.setWeakProtocolDetected(true);

        List<SecurityFinding> findings = weakProtocolRule.evaluate(scan, null);
        assertEquals(1, findings.size(), "Finding must be generated for TLS 1.0");
        SecurityFinding finding = findings.get(0);
        assertEquals("PROTO_WEAK_VERSION", finding.getRuleCode());
        assertEquals("HIGH", finding.getSeverity(), "Finding severity for outdated protocol must be HIGH");
        assertEquals(25, finding.getPoints(), "Points for deprecated protocol must be 25");
        assertTrue(finding.getEvidence().contains("TLSv1.0"), "Evidence must indicate TLS 1.0");
        assertTrue(finding.getRecommendation().contains("Disable TLS 1.0"));

        // Check environment: if JVM disables TLSv1 by policy, report environment limitation
        boolean disabledInJvm = isProtocolDisabledInJvm("TLSv1");
        if (disabledInJvm) {
            // Environment limitation: Java 21 disables TLSv1 in jdk.tls.disabledAlgorithms
            assertFalse(configurationScanner.probeProtocol("127.0.0.1", 1234, "TLSv1.0"),
                    "Probe must safely return false and not throw NoSuchAlgorithmException");
        }
    }

    // =========================================================================
    // TC-12: TLS 1.1 Detection
    // =========================================================================
    @Test
    @DisplayName("TC-12: TLS 1.1 support detection and outdated classification finding")
    void testTC12_Tls11DetectionAndClassification() {
        // Verify protocol is recognized as outdated by the scanner
        assertTrue(configurationScanner.isOutdatedProtocol("TLSv1.1"), "TLSv1.1 must be recognized as outdated");

        // Verify finding generation when TLS 1.1 is negotiated or supported
        TLSScanResult scan = new TLSScanResult();
        scan.setId(102L);
        scan.setWebsiteId(1L);
        scan.setTlsVersion("TLSv1.1");
        scan.setSupportedProtocols("TLSv1.1, TLSv1.2");
        scan.setWeakProtocolDetected(true);

        List<SecurityFinding> findings = weakProtocolRule.evaluate(scan, null);
        assertEquals(1, findings.size(), "Finding must be generated for TLS 1.1");
        SecurityFinding finding = findings.get(0);
        assertEquals("PROTO_WEAK_VERSION", finding.getRuleCode());
        assertEquals("HIGH", finding.getSeverity());
        assertEquals(25, finding.getPoints());
        assertTrue(finding.getEvidence().contains("TLSv1.1"));

        // Distinguish negotiated vs supported: even if negotiated is TLS 1.2, supported TLS 1.1 must flag
        TLSScanResult scanSupportedOnly = new TLSScanResult();
        scanSupportedOnly.setId(103L);
        scanSupportedOnly.setWebsiteId(1L);
        scanSupportedOnly.setTlsVersion("TLSv1.2"); // Negotiated modern
        scanSupportedOnly.setSupportedProtocols("TLSv1.1, TLSv1.2, TLSv1.3"); // But server also supports TLS 1.1
        scanSupportedOnly.setWeakProtocolDetected(true);

        List<SecurityFinding> supportedFindings = weakProtocolRule.evaluate(scanSupportedOnly, null);
        assertEquals(1, supportedFindings.size(), "Supported TLS 1.1 must be flagged even if TLS 1.2 was negotiated");
    }

    // =========================================================================
    // TC-13: TLS 1.2 Detection
    // =========================================================================
    @Test
    @DisplayName("TC-13: TLS 1.2 detection against controlled server; verified NOT outdated")
    void testTC13_Tls12DetectionAgainstControlledServer() throws Exception {
        // Spin up controlled local server supporting ONLY TLS 1.2
        try (TestTlsServer server = new TestTlsServer(serverSslContext, new String[]{"TLSv1.2"})) {
            TLSInspector.InspectionOutcome outcome = tlsInspector.inspect(1L, "127.0.0.1", server.getPort());

            assertNotNull(outcome);
            TLSScanResult scan = outcome.scanResult();
            assertEquals("SUCCESS", scan.getConnectionStatus());
            assertEquals("TLSv1.2", scan.getTlsVersion(), "Negotiated version must be TLSv1.2");
            assertNotNull(scan.getCipherSuite(), "Negotiated cipher suite must be captured");

            // Ensure TLS 1.2 is NOT classified as outdated
            assertFalse(configurationScanner.isOutdatedProtocol("TLSv1.2"));
            assertFalse(scan.isWeakProtocolDetected(), "TLS 1.2 must not be flagged as weak");

            List<SecurityFinding> findings = weakProtocolRule.evaluate(scan, outcome.certificateDetails());
            assertTrue(findings.isEmpty(), "TLS 1.2 must generate NO outdated protocol findings");
        }
    }

    // =========================================================================
    // TC-14: TLS 1.3 Detection
    // =========================================================================
    @Test
    @DisplayName("TC-14: TLS 1.3 detection against controlled server; protocol and cipher stored correctly")
    void testTC14_Tls13DetectionAgainstControlledServer() throws Exception {
        // Spin up controlled local server supporting ONLY TLS 1.3
        try (TestTlsServer server = new TestTlsServer(serverSslContext, new String[]{"TLSv1.3"})) {
            TLSInspector.InspectionOutcome outcome = tlsInspector.inspect(1L, "127.0.0.1", server.getPort());

            assertNotNull(outcome);
            TLSScanResult scan = outcome.scanResult();
            assertEquals("SUCCESS", scan.getConnectionStatus());
            assertEquals("TLSv1.3", scan.getTlsVersion(), "Negotiated version must be TLSv1.3");
            assertNotNull(scan.getCipherSuite(), "Negotiated cipher suite must be recorded");
            assertTrue(scan.getCipherSuite().startsWith("TLS_AES_") || scan.getCipherSuite().startsWith("TLS_CHACHA20_"),
                    "TLS 1.3 must negotiate a standard AEAD cipher suite");

            // Verify stored protocols and absence of false warnings
            assertFalse(configurationScanner.isOutdatedProtocol("TLSv1.3"));
            assertFalse(scan.isWeakProtocolDetected(), "TLS 1.3 must not trigger weak protocol warning");

            List<SecurityFinding> findings = weakProtocolRule.evaluate(scan, outcome.certificateDetails());
            assertTrue(findings.isEmpty(), "TLS 1.3 must produce NO outdated protocol findings");
        }
    }

    // =========================================================================
    // TC-15: Weak Cipher Detection
    // =========================================================================
    @Test
    @DisplayName("TC-15: Live controlled TLS server with deprecated CBC cipher is detected and flagged")
    void testTC15_LiveControlledServerWithCbcCipher() throws Exception {
        // CBC cipher supported by Java 21 JSSE
        String cbcCipher = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
        assumeTrue(configurationScanner.isCipherSupportedByJvm(cbcCipher),
                "Environment test: CBC cipher must be supported by the current JVM");

        try (TestTlsServer server = new TestTlsServer(serverSslContext, new String[]{"TLSv1.2"}, new String[]{cbcCipher})) {
            TLSInspector.InspectionOutcome outcome = tlsInspector.inspect(1L, "127.0.0.1", server.getPort());

            assertNotNull(outcome);
            TLSScanResult scan = outcome.scanResult();
            assertEquals("SUCCESS", scan.getConnectionStatus());
            assertEquals("TLSv1.2", scan.getTlsVersion());
            assertEquals(cbcCipher, scan.getCipherSuite(), "CBC cipher suite must be negotiated");

            // Evaluate through WeakCipherRule
            List<SecurityFinding> findings = weakCipherRule.evaluate(scan, outcome.certificateDetails());
            assertEquals(1, findings.size(), "Negotiated CBC cipher must generate a weak cipher finding");

            SecurityFinding finding = findings.get(0);
            assertEquals("CIPH_WEAK_SUITE", finding.getRuleCode());
            assertEquals("HIGH", finding.getSeverity());
            assertEquals(20, finding.getPoints());
            assertTrue(finding.getDescription().contains("CBC-mode cipher"));
            assertTrue(finding.getRecommendation().contains("AEAD"));
        }
    }

    @ParameterizedTest(name = "Weak cipher detection: {0}")
    @ValueSource(strings = {
            "SSL_RSA_WITH_RC4_128_SHA",
            "SSL_RSA_WITH_RC4_128_MD5",
            "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
            "SSL_RSA_EXPORT_WITH_RC4_40_MD5",
            "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
            "SSL_RSA_WITH_NULL_SHA",
            "TLS_RSA_WITH_NULL_MD5",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
    })
    @DisplayName("TC-15: Comprehensive detection across RC4, 3DES, DES, EXPORT, NULL, MD5, and CBC")
    void testTC15_WeakCipherCategoriesDetection(String weakCipherSuite) {
        TLSScanResult scan = new TLSScanResult();
        scan.setId(105L);
        scan.setWebsiteId(1L);
        scan.setCipherSuite(weakCipherSuite);

        List<SecurityFinding> findings = weakCipherRule.evaluate(scan, null);
        assertEquals(1, findings.size(), "Weak cipher suite '" + weakCipherSuite + "' must be detected");

        SecurityFinding finding = findings.get(0);
        assertEquals("CIPH_WEAK_SUITE", finding.getRuleCode());
        assertEquals("HIGH", finding.getSeverity());
        assertEquals(20, finding.getPoints());
        assertTrue(finding.getEvidence().contains(weakCipherSuite));
        assertNotNull(finding.getRecommendation());
    }

    @Test
    @DisplayName("TC-15: Unsupported cipher suites are reported as UNAVAILABLE, not secure or detected")
    void testTC15_UnsupportedCipherSuitesReportedAsUnavailable() {
        // Test ciphers removed/disabled in Java 21
        String[] legacyCiphers = {
                "SSL_RSA_WITH_RC4_128_MD5",
                "TLS_RSA_WITH_NULL_SHA",
                "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
                "SSL_RSA_WITH_DES_CBC_SHA",
                "NON_EXISTENT_CIPHER_SUITE_XYZ"
        };

        for (String cipher : legacyCiphers) {
            TLSConfigurationScanner.CipherAnalysis analysis = configurationScanner.analyzeCipherSuite(cipher);
            assertFalse(analysis.isSupportedByJvm(), "Legacy cipher '" + cipher + "' must not be reported as supported in Java 21");
            assertEquals("UNAVAILABLE", analysis.status(), "Legacy cipher must have status UNAVAILABLE");
            assertNotEquals("AVAILABLE_SECURE", analysis.status(), "Legacy cipher must NEVER be reported as AVAILABLE_SECURE");
        }
    }

    @Test
    @DisplayName("TC-15: Modern AEAD cipher suites are classified as AVAILABLE_SECURE with zero findings")
    void testTC15_SecureAeadCiphersProduceNoFindings() {
        String[] secureCiphers = {
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        };

        for (String cipher : secureCiphers) {
            TLSScanResult scan = new TLSScanResult();
            scan.setId(106L);
            scan.setWebsiteId(1L);
            scan.setCipherSuite(cipher);

            List<SecurityFinding> findings = weakCipherRule.evaluate(scan, null);
            assertTrue(findings.isEmpty(), "Secure AEAD cipher '" + cipher + "' must produce 0 findings");

            TLSConfigurationScanner.CipherAnalysis analysis = configurationScanner.analyzeCipherSuite(cipher);
            assertTrue(analysis.isSupportedByJvm(), "Cipher '" + cipher + "' is supported by JVM");
            assertFalse(analysis.isWeakOrDeprecated(), "AEAD cipher is not weak");
            assertEquals("AVAILABLE_SECURE", analysis.status(), "AEAD cipher must have status AVAILABLE_SECURE");
        }
    }
}
