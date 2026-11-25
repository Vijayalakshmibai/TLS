package com.tlsmonitor.inventory;

import com.tlsmonitor.alerts.service.AlertService;
import com.tlsmonitor.common.exception.InvalidDomainException;
import com.tlsmonitor.common.exception.SSRFSecurityException;
import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inspection.tls.CertificateExtractor;
import com.tlsmonitor.inspection.tls.TLSConfigurationScanner;
import com.tlsmonitor.inspection.tls.TLSInspector;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.inventory.repository.WebsiteRepository;
import com.tlsmonitor.inventory.service.WebsiteService;
import com.tlsmonitor.inventory.service.WebsiteValidationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Functional tests for TC-16 to TC-20:
 * - TC-16: Invalid Website Input & Rejection
 * - TC-17: Private and Loopback IP Blocking
 * - TC-18: Metadata and Restricted Address Blocking
 * - TC-19: DNS Rebinding Protection
 * - TC-20: Redirect Protection
 */
@ExtendWith(MockitoExtension.class)
public class WebsiteValidationAndSsrfScenariosTest {

    private WebsiteValidationService validationService;

    @Mock
    private WebsiteRepository websiteRepository;

    @Mock
    private AlertService alertService;

    private CertificateExtractor certificateExtractor;
    private TLSConfigurationScanner configurationScanner;
    private WebsiteService websiteService;
    private TLSInspector tlsInspector;

    @BeforeEach
    void setUp() {
        validationService = new WebsiteValidationService();
        certificateExtractor = new CertificateExtractor();
        configurationScanner = new TLSConfigurationScanner();
        websiteService = new WebsiteService(websiteRepository, validationService, alertService);
        tlsInspector = new TLSInspector(certificateExtractor, configurationScanner, validationService);
    }

    // =========================================================================
    // TC-16: Invalid Website Input
    // =========================================================================
    @Nested
    @DisplayName("TC-16: Invalid Website Input & Rejection")
    class InvalidWebsiteInputTests {

        @Test
        @DisplayName("TC-16.1: Empty and blank inputs must be rejected")
        void testEmptyAndBlankInputsRejected() {
            assertThrows(InvalidDomainException.class, () -> validationService.normalizeAndValidate(null));
            assertThrows(InvalidDomainException.class, () -> validationService.normalizeAndValidate(""));
            assertThrows(InvalidDomainException.class, () -> validationService.normalizeAndValidate("   "));
            assertThrows(InvalidDomainException.class, () -> validationService.normalizeAndValidate("\t\n"));
        }

        @ParameterizedTest(name = "TC-16.2: Invalid domain syntax {0} must be rejected")
        @ValueSource(strings = {
                "not_a_valid_domain!!",
                "-invalid.com",
                "invalid-.com",
                "invalid..com",
                "..com",
                "http://[invalid",
                "https://",
                ":::",
                "http://:80"
        })
        void testInvalidDomainSyntaxRejected(String invalidInput) {
            assertThrows(InvalidDomainException.class, () -> validationService.normalizeAndValidate(invalidInput));
        }

        @ParameterizedTest(name = "TC-16.3: Unsupported URL scheme {0} must be rejected")
        @ValueSource(strings = {
                "ftp://files.example.com",
                "file:///etc/passwd",
                "gopher://gopher.example.com",
                "ldap://ldap.example.com/dc=example",
                "javascript:alert(1)",
                "data:text/html,<h1>Hello</h1>"
        })
        void testUnsupportedSchemesRejected(String unsupportedSchemeUrl) {
            InvalidDomainException ex = assertThrows(InvalidDomainException.class,
                    () -> validationService.normalizeAndValidate(unsupportedSchemeUrl));
            assertTrue(ex.getMessage().toLowerCase().contains("unsupported url scheme") ||
                    ex.getMessage().toLowerCase().contains("malformed") ||
                    ex.getMessage().toLowerCase().contains("invalid"));
        }

        @ParameterizedTest(name = "TC-16.4: Out-of-range port {0} must be rejected")
        @ValueSource(strings = {
                "example.com:0",
                "example.com:-1",
                "example.com:65536",
                "example.com:70000",
                "example.com:abc"
        })
        void testInvalidPortsRejected(String invalidPortInput) {
            assertThrows(InvalidDomainException.class,
                    () -> validationService.normalizeAndValidate(invalidPortInput));
        }

        @Test
        @DisplayName("TC-16.5: Duplicate website registrations must be prevented case-insensitively")
        void testDuplicateWebsiteRegistrationPrevented() {
            Website existingSite = new Website("example.com", "https://example.com", "Existing");
            when(websiteRepository.existsByDomainIgnoreCase("example.com")).thenReturn(true);

            Website duplicateAttempt = new Website("EXAMPLE.COM", "https://example.com", "Duplicate");
            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                    () -> websiteService.addWebsite(duplicateAttempt));

            assertTrue(ex.getMessage().contains("already registered"));
            verify(websiteRepository, never()).save(any());
        }

        @Test
        @DisplayName("TC-16.6: Invalid inputs must fail fast before triggering TLS connections")
        void testInvalidInputDoesNotTriggerTlsConnection() {
            // When domain fails validation in service, website is not created and no scan can be executed
            assertThrows(InvalidDomainException.class, () -> {
                Website site = new Website();
                site.setDomain("not_a_valid_domain!!");
                websiteService.addWebsite(site);
            });
            verify(websiteRepository, never()).save(any());
        }
    }

    // =========================================================================
    // TC-17: Private and Loopback IP Blocking
    // =========================================================================
    @Nested
    @DisplayName("TC-17: Private and Loopback IP Blocking")
    class PrivateAndLoopbackBlockingTests {

        @ParameterizedTest(name = "TC-17.1: IPv4 loopback {0} must be blocked before connection")
        @ValueSource(strings = {
                "127.0.0.1",
                "127.0.0.2",
                "127.255.255.254",
                "http://127.0.0.1:8080",
                "https://127.0.0.1:443"
        })
        void testIPv4LoopbackBlocked(String loopbackInput) {
            SSRFSecurityException ex = assertThrows(SSRFSecurityException.class,
                    () -> validationService.normalizeAndValidate(loopbackInput));
            assertTrue(ex.getMessage().toLowerCase().contains("loopback") || ex.getMessage().toLowerCase().contains("ssrf"));
        }

        @ParameterizedTest(name = "TC-17.2: IPv6 loopback {0} must be blocked")
        @ValueSource(strings = {
                "::1",
                "[::1]",
                "http://[::1]",
                "https://[::1]:8443",
                "[::1]:443"
        })
        void testIPv6LoopbackBlocked(String ipv6Loopback) {
            SSRFSecurityException ex = assertThrows(SSRFSecurityException.class,
                    () -> validationService.normalizeAndValidate(ipv6Loopback));
            assertTrue(ex.getMessage().toLowerCase().contains("loopback") || ex.getMessage().toLowerCase().contains("::1"));
        }

        @ParameterizedTest(name = "TC-17.3: RFC 1918 10.0.0.0/8 private addresses {0} must be blocked")
        @ValueSource(strings = {
                "10.0.0.1",
                "10.254.254.254",
                "10.10.10.10",
                "https://10.0.0.1:8443"
        })
        void testClassAPrivateBlocked(String classAPrivate) {
            SSRFSecurityException ex = assertThrows(SSRFSecurityException.class,
                    () -> validationService.normalizeAndValidate(classAPrivate));
            assertTrue(ex.getMessage().toLowerCase().contains("rfc1918") || ex.getMessage().toLowerCase().contains("private"));
        }

        @ParameterizedTest(name = "TC-17.4: RFC 1918 172.16.0.0/12 private addresses {0} must be blocked")
        @ValueSource(strings = {
                "172.16.0.1",
                "172.20.10.5",
                "172.31.255.254",
                "https://172.16.0.1"
        })
        void testClassBPrivateBlocked(String classBPrivate) {
            SSRFSecurityException ex = assertThrows(SSRFSecurityException.class,
                    () -> validationService.normalizeAndValidate(classBPrivate));
            assertTrue(ex.getMessage().toLowerCase().contains("rfc1918") || ex.getMessage().toLowerCase().contains("private"));
        }

        @ParameterizedTest(name = "TC-17.5: RFC 1918 192.168.0.0/16 private addresses {0} must be blocked")
        @ValueSource(strings = {
                "192.168.0.1",
                "192.168.1.1",
                "192.168.100.254",
                "https://192.168.1.1:443"
        })
        void testClassCPrivateBlocked(String classCPrivate) {
            SSRFSecurityException ex = assertThrows(SSRFSecurityException.class,
                    () -> validationService.normalizeAndValidate(classCPrivate));
            assertTrue(ex.getMessage().toLowerCase().contains("rfc1918") || ex.getMessage().toLowerCase().contains("private"));
        }

        @ParameterizedTest(name = "TC-17.6: Link-local addresses {0} must be blocked")
        @ValueSource(strings = {
                "169.254.169.254",
                "169.254.1.1",
                "169.254.254.254",
                "https://169.254.169.254"
        })
        void testLinkLocalBlocked(String linkLocalInput) {
            SSRFSecurityException ex = assertThrows(SSRFSecurityException.class,
                    () -> validationService.normalizeAndValidate(linkLocalInput));
            assertTrue(ex.getMessage().toLowerCase().contains("link-local") || ex.getMessage().toLowerCase().contains("metadata"));
        }

        @Test
        @DisplayName("TC-17.7: IPv4-mapped IPv6 addresses must be unwrapped and blocked")
        void testIPv4MappedIPv6Blocked() throws Exception {
            InetAddress mappedLoopback = InetAddress.getByName("::ffff:127.0.0.1");
            assertThrows(SSRFSecurityException.class, () -> validationService.validateIPAgainstSSRF(mappedLoopback));

            InetAddress mappedPrivate = InetAddress.getByName("::ffff:10.0.0.1");
            assertThrows(SSRFSecurityException.class, () -> validationService.validateIPAgainstSSRF(mappedPrivate));

            InetAddress mappedMetadata = InetAddress.getByName("::ffff:169.254.169.254");
            assertThrows(SSRFSecurityException.class, () -> validationService.validateIPAgainstSSRF(mappedMetadata));
        }

        @Test
        @DisplayName("TC-17.8: IPv6 Unique Local Addresses (fc00::/7) must be blocked")
        void testIPv6UniqueLocalBlocked() throws Exception {
            InetAddress ula1 = InetAddress.getByName("fc00::1");
            assertThrows(SSRFSecurityException.class, () -> validationService.validateIPAgainstSSRF(ula1));

            InetAddress ula2 = InetAddress.getByName("fd12:3456:789a:1::1");
            assertThrows(SSRFSecurityException.class, () -> validationService.validateIPAgainstSSRF(ula2));
        }
    }

    // =========================================================================
    // TC-18: Metadata and Restricted Address Blocking
    // =========================================================================
    @Nested
    @DisplayName("TC-18: Metadata and Restricted Address Blocking")
    class MetadataAndRestrictedAddressBlockingTests {

        @ParameterizedTest(name = "TC-18.1: Cloud metadata hostnames {0} must be blocked")
        @ValueSource(strings = {
                "metadata.google.internal",
                "instance-data",
                "metadata",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://instance-data/latest/meta-data/"
        })
        void testCloudMetadataHostnamesBlocked(String metadataHost) {
            SSRFSecurityException ex = assertThrows(SSRFSecurityException.class,
                    () -> validationService.normalizeAndValidate(metadataHost));
            assertTrue(ex.getMessage().contains("SSRF Policy Violation"));
        }

        @ParameterizedTest(name = "TC-18.2: Internal and reserved TLDs {0} must be blocked")
        @ValueSource(strings = {
                "server.internal",
                "gateway.local",
                "payroll.corp",
                "router.lan",
                "nas.home",
                "database.private",
                "test.localhost"
        })
        void testInternalTLDsBlocked(String internalDomain) {
            SSRFSecurityException ex = assertThrows(SSRFSecurityException.class,
                    () -> validationService.normalizeAndValidate(internalDomain));
            assertTrue(ex.getMessage().contains("SSRF Policy Violation"));
        }

        @ParameterizedTest(name = "TC-18.3: Multicast and reserved IP ranges {0} must be blocked")
        @ValueSource(strings = {
                "224.0.0.1",
                "239.255.255.250",
                "0.0.0.0",
                "100.64.0.1",
                "100.100.100.100",
                "192.0.0.1",
                "198.18.0.1",
                "240.0.0.1",
                "255.255.255.255"
        })
        void testMulticastAndReservedIPsBlocked(String reservedIp) {
            SSRFSecurityException ex = assertThrows(SSRFSecurityException.class,
                    () -> validationService.normalizeAndValidate(reservedIp));
            assertTrue(ex.getMessage().contains("SSRF Policy"));
        }

        @Test
        @DisplayName("TC-18.4: Direct inspection of metadata destination must be rejected before connection")
        void testTLSInspectorBlocksMetadataDestination() {
            TLSInspector.InspectionOutcome outcome = tlsInspector.inspect(1L, "169.254.169.254", 443);
            assertNotNull(outcome.scanResult());
            assertEquals("BLOCKED_SSRF", outcome.scanResult().getConnectionStatus());
            assertTrue(outcome.scanResult().getTrustError().contains("SSRF Policy"));
            assertNull(outcome.certificateDetails());
        }
    }

    // =========================================================================
    // TC-19: DNS Rebinding Protection
    // =========================================================================
    @Nested
    @DisplayName("TC-19: DNS Rebinding Protection")
    class DnsRebindingProtectionTests {

        @Test
        @DisplayName("TC-19.1: Validated public IP is pinned in NormalizedTarget to prevent rebinding")
        void testPinnedIpCapturedInNormalizedTarget() throws Exception {
            InetAddress publicIp = InetAddress.getByName("93.184.216.34");
            WebsiteValidationService.DnsResolver mockResolver = host -> new InetAddress[]{publicIp};

            WebsiteValidationService.NormalizedTarget target =
                    validationService.normalizeAndValidate("example.com", mockResolver);

            assertEquals("example.com", target.domain());
            assertEquals(443, target.port());
            assertNotNull(target.validatedAddress());
            assertEquals(publicIp, target.validatedAddress());
        }

        @Test
        @DisplayName("TC-19.2: DNS Rebinding returning private address on validation is blocked")
        void testDnsRebindingToPrivateAddressIsBlocked() {
            // Simulated attacker DNS that resolves to a private IP (e.g. 127.0.0.1)
            WebsiteValidationService.DnsResolver rebindingResolver = host -> new InetAddress[]{
                    InetAddress.getByAddress(new byte[]{127, 0, 0, 1})
            };

            SSRFSecurityException ex = assertThrows(SSRFSecurityException.class,
                    () -> validationService.normalizeAndValidate("rebind.attacker.com", rebindingResolver));
            assertTrue(ex.getMessage().contains("Loopback addresses are blocked"));
        }

        @Test
        @DisplayName("TC-19.3: Multi-A record containing any restricted IP is rejected")
        void testMultiARecordWithRestrictedIpIsRejected() throws Exception {
            // DNS returns both a public IP and an internal metadata IP
            InetAddress publicIp = InetAddress.getByName("93.184.216.34");
            InetAddress metadataIp = InetAddress.getByAddress(new byte[]{(byte) 169, (byte) 254, (byte) 169, (byte) 254});

            WebsiteValidationService.DnsResolver dualResolver = host -> new InetAddress[]{publicIp, metadataIp};

            SSRFSecurityException ex = assertThrows(SSRFSecurityException.class,
                    () -> validationService.normalizeAndValidate("dual-rebind.attacker.com", dualResolver));
            assertTrue(ex.getMessage().contains("169.254") || ex.getMessage().contains("Link-local"));
        }

        @Test
        @DisplayName("TC-19.4: Time-of-check to time-of-use (TOCTOU) DNS Rebinding simulation")
        void testToctouDnsRebindingBlockedAtConnectionTime() throws Exception {
            // Simulates DNS that returns public IP on first call, then rebinds to 127.0.0.1 on second call
            AtomicInteger lookupCount = new AtomicInteger(0);
            InetAddress publicIp = InetAddress.getByName("93.184.216.34");
            InetAddress privateIp = InetAddress.getByName("127.0.0.1");

            WebsiteValidationService.DnsResolver flipperResolver = host -> {
                if (lookupCount.getAndIncrement() == 0) {
                    return new InetAddress[]{publicIp};
                } else {
                    return new InetAddress[]{privateIp};
                }
            };

            // First lookup is valid public IP
            WebsiteValidationService.NormalizedTarget target =
                    validationService.normalizeAndValidate("flipping-domain.com", flipperResolver);
            assertEquals(publicIp, target.validatedAddress());

            // Second lookup simulates rebinding when re-validated: must be blocked!
            assertThrows(SSRFSecurityException.class,
                    () -> validationService.validateHostDNSAgainstSSRF("flipping-domain.com", flipperResolver));
        }
    }

    // =========================================================================
    // TC-20: Redirect Protection
    // =========================================================================
    @Nested
    @DisplayName("TC-20: Redirect Protection")
    class RedirectProtectionTests {

        @Test
        @DisplayName("TC-20.1: Safe relative redirect is validated and permitted")
        void testSafeRelativeRedirectPermitted() throws Exception {
            InetAddress publicIp = InetAddress.getByName("93.184.216.34");
            WebsiteValidationService.DnsResolver resolver = host -> new InetAddress[]{publicIp};

            WebsiteValidationService.NormalizedTarget result =
                    validationService.validateRedirectTarget("https://example.com/start", "/auth/login", resolver);

            assertEquals("example.com", result.domain());
            assertEquals(443, result.port());
            assertEquals("https://example.com", result.normalizedUrl());
        }

        @Test
        @DisplayName("TC-20.2: Redirect to loopback (127.0.0.1) is blocked before connection")
        void testRedirectToLoopbackBlocked() {
            SSRFSecurityException ex = assertThrows(SSRFSecurityException.class,
                    () -> validationService.validateRedirectTarget("https://example.com", "http://127.0.0.1:8080/admin"));
            assertTrue(ex.getMessage().contains("Loopback") || ex.getMessage().contains("SSRF"));
        }

        @Test
        @DisplayName("TC-20.3: Redirect to cloud metadata (169.254.169.254) is blocked")
        void testRedirectToCloudMetadataBlocked() {
            SSRFSecurityException ex = assertThrows(SSRFSecurityException.class,
                    () -> validationService.validateRedirectTarget("https://example.com", "http://169.254.169.254/latest/meta-data/"));
            assertTrue(ex.getMessage().contains("169.254") || ex.getMessage().contains("Link-local") || ex.getMessage().contains("metadata"));
        }

        @Test
        @DisplayName("TC-20.4: Redirect to private RFC 1918 (10.0.0.1) is blocked")
        void testRedirectToPrivateNetworkBlocked() {
            SSRFSecurityException ex = assertThrows(SSRFSecurityException.class,
                    () -> validationService.validateRedirectTarget("https://example.com", "http://10.0.0.1/private-data"));
            assertTrue(ex.getMessage().contains("RFC1918") || ex.getMessage().contains("private"));
        }

        @Test
        @DisplayName("TC-20.5: Redirect to internal hostname (metadata.google.internal) is blocked")
        void testRedirectToInternalHostnameBlocked() {
            SSRFSecurityException ex = assertThrows(SSRFSecurityException.class,
                    () -> validationService.validateRedirectTarget("https://example.com", "http://metadata.google.internal/computeMetadata/v1/"));
            assertTrue(ex.getMessage().contains("SSRF Policy Violation"));
        }

        @Test
        @DisplayName("TC-20.6: Redirect to non-HTTP/HTTPS schemes (ftp, file) is blocked")
        void testRedirectToNonHttpSchemesBlocked() {
            assertThrows(SSRFSecurityException.class,
                    () -> validationService.validateRedirectTarget("https://example.com", "ftp://backup.corp/secrets"));
            assertThrows(SSRFSecurityException.class,
                    () -> validationService.validateRedirectTarget("https://example.com", "file:///etc/shadow"));
            assertThrows(SSRFSecurityException.class,
                    () -> validationService.validateRedirectTarget("https://example.com", "javascript:alert(document.cookie)"));
        }

        @Test
        @DisplayName("TC-20.7: Empty or blank redirect header is rejected")
        void testEmptyRedirectHeaderRejected() {
            assertThrows(SSRFSecurityException.class,
                    () -> validationService.validateRedirectTarget("https://example.com", ""));
            assertThrows(SSRFSecurityException.class,
                    () -> validationService.validateRedirectTarget("https://example.com", null));
        }
    }
}
