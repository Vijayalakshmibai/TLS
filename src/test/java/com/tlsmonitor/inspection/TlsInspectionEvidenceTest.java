package com.tlsmonitor.inspection;

import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inspection.entity.ValidationStatus;
import com.tlsmonitor.inspection.tls.CertificateExtractor;
import com.tlsmonitor.inspection.tls.TLSConfigurationScanner;
import com.tlsmonitor.inspection.tls.TLSInspector;
import com.tlsmonitor.inventory.service.WebsiteValidationService;
import com.tlsmonitor.risk.rules.HostnameMismatchRule;
import com.tlsmonitor.risk.rules.UntrustedChainRule;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

class TlsInspectionEvidenceTest {

    @Test
    void connectionResetBeforeCertificateLeavesValidationsUnevaluated() throws Exception {
        try (ServerSocket server = new ServerSocket(0, 10, InetAddress.getByName("127.0.0.1"))) {
            AtomicBoolean accepting = new AtomicBoolean(true);
            Thread resetServer = new Thread(() -> acceptAndReset(server, accepting), "tls-reset-test-server");
            resetServer.setDaemon(true);
            resetServer.start();

            TLSInspector inspector = new TLSInspector(
                    new CertificateExtractor(),
                    new TLSConfigurationScanner(),
                    new WebsiteValidationService(true));

            TLSInspector.InspectionOutcome outcome = inspector.inspect(1L, "127.0.0.1", server.getLocalPort());

            accepting.set(false);
            server.close();
            resetServer.join(1000);

            assertEquals("CONNECTION_FAILED", outcome.scanResult().getConnectionStatus());
            assertEquals(ValidationStatus.NOT_EVALUATED, outcome.scanResult().getHostnameValidationStatus());
            assertEquals(ValidationStatus.NOT_EVALUATED, outcome.scanResult().getTrustValidationStatus());
            assertNull(outcome.certificateDetails());
            assertTrue(new HostnameMismatchRule().evaluate(outcome.scanResult(), null).isEmpty());
            assertTrue(new UntrustedChainRule().evaluate(outcome.scanResult(), null).isEmpty());
        }
    }

    private void acceptAndReset(ServerSocket server, AtomicBoolean accepting) {
        while (accepting.get()) {
            try (Socket ignored = server.accept()) {
                // Closing each accepted socket simulates a peer reset before sending a TLS certificate.
            } catch (IOException e) {
                if (accepting.get()) {
                    throw new IllegalStateException("TLS reset test server failed.", e);
                }
                return;
            }
        }
    }
}
