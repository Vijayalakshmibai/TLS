package com.tlsmonitor;

import com.tlsmonitor.common.entity.DatabaseHealthCheck;
import com.tlsmonitor.common.repository.DatabaseHealthCheckRepository;
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
}
