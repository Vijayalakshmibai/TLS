package com.tlsmonitor.inventory;

import com.tlsmonitor.common.exception.InvalidDomainException;
import com.tlsmonitor.common.exception.SSRFSecurityException;
import com.tlsmonitor.inventory.service.WebsiteValidationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class WebsiteValidationServiceTest {

    private WebsiteValidationService validationService;

    @BeforeEach
    void setUp() {
        validationService = new WebsiteValidationService();
    }

    @Test
    void testNormalizeDomainStandard() {
        WebsiteValidationService.NormalizedTarget target = validationService.normalizeAndValidate("https://example.com/");
        assertEquals("example.com", target.domain());
        assertEquals(443, target.port());
        assertEquals("https://example.com", target.normalizedUrl());
    }

    @Test
    void testNormalizeDomainWithPort() {
        WebsiteValidationService.NormalizedTarget target = validationService.normalizeAndValidate("example.com:8443");
        assertEquals("example.com", target.domain());
        assertEquals(8443, target.port());
        assertEquals("https://example.com:8443", target.normalizedUrl());
    }

    @Test
    void testBlankInputThrowsInvalidDomainException() {
        assertThrows(InvalidDomainException.class, () -> validationService.normalizeAndValidate("   "));
        assertThrows(InvalidDomainException.class, () -> validationService.normalizeAndValidate(null));
    }

    @Test
    void testInvalidSyntaxThrowsInvalidDomainException() {
        assertThrows(InvalidDomainException.class, () -> validationService.normalizeAndValidate("not_a_valid_domain!!"));
    }

    @Test
    void testSSRFBlocksLocalhost() {
        assertThrows(SSRFSecurityException.class, () -> validationService.normalizeAndValidate("localhost"));
        assertThrows(SSRFSecurityException.class, () -> validationService.normalizeAndValidate("127.0.0.1"));
        assertThrows(SSRFSecurityException.class, () -> validationService.normalizeAndValidate("::1"));
    }

    @Test
    void testSSRFBlocksPrivateAndMetadataIPs() {
        assertThrows(SSRFSecurityException.class, () -> validationService.normalizeAndValidate("10.0.0.1"));
        assertThrows(SSRFSecurityException.class, () -> validationService.normalizeAndValidate("192.168.1.1"));
        assertThrows(SSRFSecurityException.class, () -> validationService.normalizeAndValidate("172.16.0.1"));
        assertThrows(SSRFSecurityException.class, () -> validationService.normalizeAndValidate("169.254.169.254"));
        assertThrows(SSRFSecurityException.class, () -> validationService.normalizeAndValidate("metadata.google.internal"));
    }
}
