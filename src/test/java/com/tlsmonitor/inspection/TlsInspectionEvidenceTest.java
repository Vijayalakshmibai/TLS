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
import com.tlsmonitor.testutil.CertificateTestUtils;
import com.tlsmonitor.testutil.TestTlsServer;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.SSLContext;

import static org.junit.jupiter.api.Assertions.*;

class TlsInspectionEvidenceTest {

    @Test
    void connectionResetBeforeCertificateLeavesValidationsUnevaluated() throws Exception {
        try (ServerSocket server = new ServerSocket(0, 10, InetAddress.getByName("127.0.0.1"))) {
            AtomicBoolean accepting = new AtomicBoolean(true);
            Thread resetServer = new Thread(() -> acceptAndReset(server, accepting), "tls-reset-test-server");
            resetServer.setDaemon(true);
            resetServer.start();

            TLSInspector inspector = createInspector();

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

    @Test
    void certificateIsRetainedWhenHandshakeFailsAfterTrustManagerCapture() throws Exception {
        KeyPair serverKeyPair = CertificateTestUtils.generateRsaKeyPair();
        X509Certificate serverCertificate = CertificateTestUtils.generateSelfSignedCertificate(
                "CN=127.0.0.1",
                serverKeyPair,
                Date.from(Instant.now().minus(1, ChronoUnit.DAYS)),
                Date.from(Instant.now().plus(30, ChronoUnit.DAYS)),
                List.of("127.0.0.1"));
        KeyStore serverKeyStore = CertificateTestUtils.createKeyStore(
                serverKeyPair.getPrivate(),
                new Certificate[]{serverCertificate},
                "server",
                "changeit".toCharArray());
        SSLContext serverContext = CertificateTestUtils.createServerSslContext(
                serverKeyStore, "changeit".toCharArray());

        try (TestTlsServer server = new TestTlsServer(
                serverContext, new String[]{"TLSv1.2"}, null, true)) {
            TLSInspector inspector = createInspector();

            TLSInspector.InspectionOutcome outcome =
                    inspector.inspect(1L, "127.0.0.1", server.getPort());

            assertNotNull(outcome.certificateDetails(),
                    "The peer certificate should remain available after the server rejects the missing client certificate.");
            assertEquals("HANDSHAKE_FAILED", outcome.scanResult().getConnectionStatus());
            assertEquals(ValidationStatus.INVALID,
                    outcome.scanResult().getTrustValidationStatus());
            assertTrue(outcome.certificateDetails().getSubject().contains("127.0.0.1"));
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

    private TLSInspector createInspector() {
        TLSConfigurationScanner scanner = new TLSConfigurationScanner() {
            @Override
            public ProtocolScanReport probeProtocols(String host, int port) {
                return new ProtocolScanReport("TLSv1.2", false);
            }
        };
        return new TLSInspector(
                new CertificateExtractor(),
                scanner,
                new WebsiteValidationService(true));
    }
}
