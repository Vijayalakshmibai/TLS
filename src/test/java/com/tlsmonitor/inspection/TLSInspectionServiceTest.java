package com.tlsmonitor.inspection;

import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inspection.repository.CertificateDetailsRepository;
import com.tlsmonitor.inspection.repository.TLSScanResultRepository;
import com.tlsmonitor.inspection.service.TLSInspectionService;
import com.tlsmonitor.inspection.tls.TLSInspector;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.inventory.service.WebsiteService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TLSInspectionServiceTest {

    @Mock
    private TLSInspector tlsInspector;

    @Mock
    private TLSScanResultRepository scanResultRepository;

    @Mock
    private CertificateDetailsRepository certificateDetailsRepository;

    @Mock
    private WebsiteService websiteService;

    private TLSInspectionService inspectionService;

    @BeforeEach
    void setUp() {
        inspectionService = new TLSInspectionService(tlsInspector, scanResultRepository, certificateDetailsRepository, websiteService);
    }

    @Test
    void testPerformScanPersistsResultsAndUpdatesWebsite() {
        Website website = new Website("example.com", "https://example.com", "Test");
        website.setId(1L);

        TLSScanResult scanResult = new TLSScanResult();
        scanResult.setWebsiteId(1L);
        scanResult.setConnectionStatus("SUCCESS");
        scanResult.setTlsVersion("TLSv1.3");
        scanResult.setCipherSuite("TLS_AES_128_GCM_SHA256");

        CertificateDetails certDetails = new CertificateDetails();
        certDetails.setSubject("CN=example.com");

        when(websiteService.getWebsiteById(1L)).thenReturn(website);
        when(tlsInspector.inspect(1L, "example.com", 443))
                .thenReturn(new TLSInspector.InspectionOutcome(scanResult, certDetails));
        when(scanResultRepository.save(any(TLSScanResult.class))).thenAnswer(i -> {
            TLSScanResult r = i.getArgument(0);
            r.setId(100L);
            return r;
        });
        when(certificateDetailsRepository.save(any(CertificateDetails.class))).thenAnswer(i -> i.getArgument(0));

        TLSInspector.InspectionOutcome outcome = inspectionService.performScan(1L);

        assertNotNull(outcome);
        assertNotNull(outcome.scanResult().getId());
        assertEquals("SUCCESS", outcome.scanResult().getConnectionStatus());
        assertEquals("TLSv1.3", outcome.scanResult().getTlsVersion());
        assertEquals(100L, outcome.certificateDetails().getScanId());

        verify(scanResultRepository).save(any(TLSScanResult.class));
        verify(certificateDetailsRepository).save(any(CertificateDetails.class));
        verify(websiteService).recordScanCompleted(1L);
    }

    @Test
    void testGetScanHistoryReturnsOrderedResults() {
        TLSScanResult scan1 = new TLSScanResult();
        scan1.setId(1L);
        when(scanResultRepository.findByWebsiteIdOrderByScannedAtDesc(1L)).thenReturn(List.of(scan1));

        List<TLSScanResult> history = inspectionService.getScanHistory(1L);
        assertEquals(1, history.size());
        assertEquals(1L, history.get(0).getId());
    }
}
