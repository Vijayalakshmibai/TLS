package com.tlsmonitor.alerts;

import com.tlsmonitor.alerts.entity.Alert;
import com.tlsmonitor.alerts.repository.AlertRepository;
import com.tlsmonitor.alerts.service.AlertService;
import com.tlsmonitor.alerts.service.EmailService;
import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inspection.repository.CertificateDetailsRepository;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.inventory.repository.WebsiteRepository;
import com.tlsmonitor.reporting.service.PdfReportService;
import com.tlsmonitor.risk.entity.RiskAssessment;
import com.tlsmonitor.risk.service.RiskReportResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AlertService Unit Tests")
class AlertServiceTest {

    @Mock
    private AlertRepository alertRepository;

    @Mock
    private EmailService emailService;

    @Mock
    private WebsiteRepository websiteRepository;

    @InjectMocks
    private AlertService alertService;

    private Website website;
    private TLSScanResult scanResult;
    private CertificateDetails certDetails;
    private RiskAssessment riskAssessment;

    @BeforeEach
    void setUp() {
        website = new Website("critical-site.example.com", "https://critical-site.example.com", "Testing alert generation");
        website.setId(100L);
        website.setContactEmail("security@example.com");

        scanResult = new TLSScanResult();
        scanResult.setWebsiteId(100L);
        scanResult.setDomain("critical-site.example.com");
        scanResult.setPort(443);
        scanResult.setHostnameValid(false); // triggers HOSTNAME_MISMATCH
        scanResult.setTrustChainValid(false); // triggers UNTRUSTED_CHAIN
        scanResult.setTrustError("Self-signed certificate in chain");

        certDetails = new CertificateDetails();
        certDetails.setWebsiteId(100L);
        certDetails.setExpired(true); // triggers EXPIRED
        certDetails.setDaysRemaining(-2);

        riskAssessment = new RiskAssessment(100L, 100L, 85, "CRITICAL", 3);
    }

    @Test
    @DisplayName("Should generate alerts for expired cert, hostname mismatch, untrusted chain, and critical risk")
    void shouldGenerateAlertsForRisks() {
        when(alertRepository.existsByWebsiteIdAndAlertTypeAndStatus(eq(100L), any(), eq("PENDING"))).thenReturn(false);
        when(alertRepository.existsByWebsiteIdAndAlertTypeAndStatus(eq(100L), any(), eq("SENT"))).thenReturn(false);
        when(alertRepository.save(any(Alert.class))).thenAnswer(invocation -> {
            Alert a = invocation.getArgument(0);
            a.setId(999L);
            return a;
        });
        when(emailService.sendAlertEmail(eq("security@example.com"), any(Alert.class))).thenReturn(true);

        List<Alert> generated = alertService.processScanAlerts(website, scanResult, certDetails, riskAssessment);

        // Expect 4 alerts: EXPIRED, HOSTNAME_MISMATCH, UNTRUSTED_CHAIN, CRITICAL_RISK
        assertEquals(4, generated.size(), "Should produce 4 distinct alerts for the four critical issues");
        verify(emailService, times(4)).sendAlertEmail(eq("security@example.com"), any(Alert.class));
    }

    @Test
    @DisplayName("Should deduplicate alerts if an active alert for the same type already exists")
    void shouldDeduplicateActiveAlerts() {
        // Mock that EXPIRED alert already exists in PENDING state (general fallback first, specific match second)
        when(alertRepository.existsByWebsiteIdAndAlertTypeAndStatus(anyLong(), anyString(), anyString())).thenReturn(false);
        when(alertRepository.existsByWebsiteIdAndAlertTypeAndStatus(eq(100L), eq("EXPIRED"), eq("PENDING"))).thenReturn(true);

        when(alertRepository.save(any(Alert.class))).thenAnswer(invocation -> {
            Alert a = invocation.getArgument(0);
            a.setId(555L);
            return a;
        });

        List<Alert> generated = alertService.processScanAlerts(website, scanResult, certDetails, null);

        // EXPIRED was deduplicated; only HOSTNAME_MISMATCH and UNTRUSTED_CHAIN generated
        assertEquals(2, generated.size());
        assertTrue(generated.stream().noneMatch(a -> "EXPIRED".equals(a.getAlertType())));
    }

    @Test
    @DisplayName("Should acknowledge and resolve alerts with proper lifecycle state")
    void shouldAcknowledgeAndResolveAlerts() {
        Alert alert = new Alert(100L, "example.com", "EXPIRY_WARNING_7D", "CRITICAL", "Expiring soon");
        alert.setId(42L);
        alert.setStatus("PENDING");

        when(alertRepository.findById(42L)).thenReturn(Optional.of(alert));
        when(alertRepository.save(any(Alert.class))).thenAnswer(invocation -> invocation.getArgument(0));

        Alert acked = alertService.acknowledgeAlert(42L);
        assertEquals("ACKNOWLEDGED", acked.getStatus());

        Alert resolved = alertService.resolveAlert(42L);
        assertEquals("RESOLVED", resolved.getStatus());
        assertNotNull(resolved.getResolvedAt());
    }

    @Test
    @DisplayName("Should resolve active alerts when a website is removed")
    void shouldResolveAlertsForDeletedWebsite() {
        Alert pending = new Alert(100L, "critical-site.example.com", "CRITICAL_RISK", "CRITICAL", "Critical risk");
        Alert acknowledged = new Alert(100L, "critical-site.example.com", "HOSTNAME_MISMATCH", "HIGH", "Mismatch");
        acknowledged.setStatus("ACKNOWLEDGED");
        when(alertRepository.findByWebsiteIdAndStatusNot(100L, "RESOLVED"))
                .thenReturn(List.of(pending, acknowledged));
        when(alertRepository.save(any(Alert.class))).thenAnswer(invocation -> invocation.getArgument(0));

        alertService.resolveActiveAlertsForWebsite(100L);

        assertEquals("RESOLVED", pending.getStatus());
        assertNotNull(pending.getResolvedAt());
        assertEquals("RESOLVED", acknowledged.getStatus());
        assertNotNull(acknowledged.getResolvedAt());
        verify(alertRepository, times(2)).save(any(Alert.class));
    }

    @Test
    @DisplayName("Should auto-resolve alerts for websites already removed from inventory")
    void shouldResolveOrphanedAlertsWhenCountingActiveAlerts() {
        Alert orphaned = new Alert(100L, "deleted.example.com", "CRITICAL_RISK", "CRITICAL", "Critical risk");
        when(websiteRepository.findAll()).thenReturn(List.of());
        when(alertRepository.findByStatusNot("RESOLVED")).thenReturn(List.of(orphaned));
        when(alertRepository.countByStatus("PENDING")).thenReturn(0L);
        when(alertRepository.countByStatus("SENT")).thenReturn(0L);
        when(alertRepository.save(any(Alert.class))).thenAnswer(invocation -> invocation.getArgument(0));

        assertEquals(0, alertService.countActiveAlerts());

        assertEquals("RESOLVED", orphaned.getStatus());
        assertNotNull(orphaned.getResolvedAt());
        verify(alertRepository).save(orphaned);
    }

    @Test
    @DisplayName("Should generate PDF report, email backend recipient, and record SENT status")
    void shouldSendAlertPdfReportAndRecordSuccess() throws Exception {
        CertificateDetailsRepository certRepo = mock(CertificateDetailsRepository.class);
        RiskReportResolver riskResolver = mock(RiskReportResolver.class);
        PdfReportService pdfService = mock(PdfReportService.class);
        AlertService service = new AlertService(
                alertRepository,
                emailService,
                websiteRepository,
                certRepo,
                riskResolver,
                pdfService,
                "vijayalakshmibai0686@gmail.com"
        );

        Alert alert = new Alert(100L, "critical-site.example.com", "CRITICAL_RISK", "CRITICAL", "Score 85");
        alert.setId(77L);

        when(alertRepository.findById(77L)).thenReturn(Optional.of(alert));
        when(websiteRepository.findById(100L)).thenReturn(Optional.of(website));
        when(riskResolver.resolve(100L)).thenReturn(Optional.empty());
        when(certRepo.findFirstByWebsiteIdOrderByIdDesc(100L)).thenReturn(Optional.of(certDetails));
        when(pdfService.generateWebsiteReport(eq(website), isNull(), eq(certDetails), isNull(), eq(List.of())))
                .thenReturn("%PDF-test".getBytes());
        when(emailService.sendPdfReportEmail(eq("vijayalakshmibai0686@gmail.com"), eq(alert), any(), eq("TLS_Security_Report_critical-site.example.com.pdf")))
                .thenReturn(true);
        when(alertRepository.save(any(Alert.class))).thenAnswer(invocation -> invocation.getArgument(0));

        assertTrue(service.sendAlertPdfReport(77L));
        assertEquals("SENT", alert.getReportDeliveryStatus());
        assertNotNull(alert.getReportSentAt());
        assertEquals("SENT", alert.getStatus());
    }

    @Test
    @DisplayName("Should record FAILED status when PDF email delivery fails")
    void shouldRecordFailedStatusWhenPdfEmailFails() throws Exception {
        CertificateDetailsRepository certRepo = mock(CertificateDetailsRepository.class);
        RiskReportResolver riskResolver = mock(RiskReportResolver.class);
        PdfReportService pdfService = mock(PdfReportService.class);
        AlertService service = new AlertService(
                alertRepository,
                emailService,
                websiteRepository,
                certRepo,
                riskResolver,
                pdfService,
                "vijayalakshmibai0686@gmail.com"
        );

        Alert alert = new Alert(100L, "critical-site.example.com", "CRITICAL_RISK", "CRITICAL", "Score 85");
        alert.setId(78L);

        when(alertRepository.findById(78L)).thenReturn(Optional.of(alert));
        when(websiteRepository.findById(100L)).thenReturn(Optional.of(website));
        when(riskResolver.resolve(100L)).thenReturn(Optional.empty());
        when(certRepo.findFirstByWebsiteIdOrderByIdDesc(100L)).thenReturn(Optional.empty());
        when(pdfService.generateWebsiteReport(eq(website), isNull(), isNull(), isNull(), eq(List.of())))
                .thenReturn("%PDF-test".getBytes());
        when(emailService.sendPdfReportEmail(eq("vijayalakshmibai0686@gmail.com"), eq(alert), any(), anyString()))
                .thenReturn(false);
        when(alertRepository.save(any(Alert.class))).thenAnswer(invocation -> invocation.getArgument(0));

        assertFalse(service.sendAlertPdfReport(78L));
        assertEquals("FAILED", alert.getReportDeliveryStatus());
        assertNull(alert.getReportSentAt());
        assertEquals("PENDING", alert.getStatus());
    }
}
