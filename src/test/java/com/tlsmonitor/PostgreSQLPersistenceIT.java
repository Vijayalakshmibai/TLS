package com.tlsmonitor;

import com.tlsmonitor.common.entity.DatabaseHealthCheck;
import com.tlsmonitor.common.repository.DatabaseHealthCheckRepository;
import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inspection.repository.CertificateDetailsRepository;
import com.tlsmonitor.inspection.repository.TLSScanResultRepository;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.inventory.repository.WebsiteRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:postgresql://localhost:5432/tls_monitoring_db",
        "spring.datasource.username=postgres",
        "spring.datasource.password=",
        "spring.datasource.driver-class-name=org.postgresql.Driver",
        "spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect",
        "spring.jpa.hibernate.ddl-auto=update"
})
class PostgreSQLPersistenceIT {

    @Autowired
    private DatabaseHealthCheckRepository repository;

    @Autowired
    private WebsiteRepository websiteRepository;

    @Autowired
    private TLSScanResultRepository scanResultRepository;

    @Autowired
    private CertificateDetailsRepository certificateDetailsRepository;

    @Test
    void testPostgreSQLConnectionAndPersistence() {
        DatabaseHealthCheck healthCheck = new DatabaseHealthCheck("HEALTHY_POSTGRES_CONNECTED", LocalDateTime.now());
        DatabaseHealthCheck saved = repository.save(healthCheck);

        assertNotNull(saved.getId(), "Entity should be assigned an ID by PostgreSQL");

        Optional<DatabaseHealthCheck> retrieved = repository.findById(saved.getId());
        assertTrue(retrieved.isPresent(), "Entity should be found in PostgreSQL");
        assertEquals("HEALTHY_POSTGRES_CONNECTED", retrieved.get().getStatus());
    }

    @Test
    void testWebsitePersistenceInPostgreSQL() {
        String testDomain = "test-" + System.currentTimeMillis() + ".org";
        Website site = new Website(testDomain, "https://" + testDomain, "Integration test website");
        Website saved = websiteRepository.save(site);

        assertNotNull(saved.getId(), "Website should be persisted with generated ID");
        Optional<Website> fetched = websiteRepository.findById(saved.getId());
        assertTrue(fetched.isPresent());
        assertEquals(testDomain, fetched.get().getDomain());
        assertEquals("ACTIVE", fetched.get().getStatus());
    }

    @Test
    void testScanResultAndCertificatePersistenceInPostgreSQL() {
        TLSScanResult scan = new TLSScanResult();
        scan.setWebsiteId(1L);
        scan.setDomain("example.com");
        scan.setConnectionStatus("SUCCESS");
        scan.setTlsVersion("TLSv1.3");
        scan.setCipherSuite("TLS_AES_128_GCM_SHA256");
        scan.setHostnameValid(true);
        scan.setTrustChainValid(true);
        scan.setSupportedProtocols("TLSv1.2, TLSv1.3");
        TLSScanResult savedScan = scanResultRepository.save(scan);
        assertNotNull(savedScan.getId());

        CertificateDetails cert = new CertificateDetails();
        cert.setScanId(savedScan.getId());
        cert.setWebsiteId(1L);
        cert.setSubject("CN=example.com");
        cert.setIssuer("CN=DigiCert Global Root CA");
        cert.setKeySize(2048);
        cert.setDaysRemaining(90);
        CertificateDetails savedCert = certificateDetailsRepository.save(cert);
        assertNotNull(savedCert.getId());

        Optional<CertificateDetails> fetched = certificateDetailsRepository.findByScanId(savedScan.getId());
        assertTrue(fetched.isPresent());
        assertEquals("CN=example.com", fetched.get().getSubject());
    }
}
