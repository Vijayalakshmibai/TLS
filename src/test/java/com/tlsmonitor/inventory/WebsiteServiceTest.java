package com.tlsmonitor.inventory;

import com.tlsmonitor.common.exception.ResourceNotFoundException;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.inventory.repository.WebsiteRepository;
import com.tlsmonitor.inventory.service.WebsiteService;
import com.tlsmonitor.inventory.service.WebsiteValidationService;
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
class WebsiteServiceTest {

    @Mock
    private WebsiteRepository websiteRepository;

    @Mock
    private WebsiteValidationService validationService;

    private WebsiteService websiteService;

    @BeforeEach
    void setUp() {
        websiteService = new WebsiteService(websiteRepository, validationService);
    }

    @Test
    void testAddWebsiteSuccessful() {
        Website website = new Website();
        website.setDomain("example.com");

        when(validationService.normalizeAndValidate("example.com"))
                .thenReturn(new WebsiteValidationService.NormalizedTarget("example.com", 443, "https://example.com"));
        when(websiteRepository.existsByDomainIgnoreCase("example.com")).thenReturn(false);
        when(websiteRepository.save(any(Website.class))).thenAnswer(invocation -> invocation.getArgument(0));

        Website saved = websiteService.addWebsite(website);

        assertNotNull(saved);
        assertEquals("example.com", saved.getDomain());
        assertEquals("https://example.com", saved.getUrl());
        assertEquals(443, saved.getPort());
        assertEquals("ACTIVE", saved.getStatus());
        verify(websiteRepository).save(any(Website.class));
    }

    @Test
    void testAddDuplicateWebsiteThrowsException() {
        Website website = new Website();
        website.setDomain("example.com");

        when(validationService.normalizeAndValidate("example.com"))
                .thenReturn(new WebsiteValidationService.NormalizedTarget("example.com", 443, "https://example.com"));
        when(websiteRepository.existsByDomainIgnoreCase("example.com")).thenReturn(true);

        assertThrows(IllegalArgumentException.class, () -> websiteService.addWebsite(website));
        verify(websiteRepository, never()).save(any());
    }

    @Test
    void testGetWebsiteByIdNotFoundThrowsException() {
        when(websiteRepository.findById(999L)).thenReturn(Optional.empty());
        assertThrows(ResourceNotFoundException.class, () -> websiteService.getWebsiteById(999L));
    }

    @Test
    void testUpdateWebsite() {
        Website existing = new Website("example.com", "https://example.com", "Old Description");
        existing.setId(1L);

        when(websiteRepository.findById(1L)).thenReturn(Optional.of(existing));
        when(websiteRepository.save(any(Website.class))).thenAnswer(invocation -> invocation.getArgument(0));

        Website updateInfo = new Website();
        updateInfo.setDescription("New Description");
        updateInfo.setStatus("WARNING");

        Website updated = websiteService.updateWebsite(1L, updateInfo);
        assertEquals("New Description", updated.getDescription());
        assertEquals("WARNING", updated.getStatus());
    }

    @Test
    void testDeleteWebsite() {
        Website existing = new Website("example.com", "https://example.com", "To Delete");
        existing.setId(1L);

        when(websiteRepository.findById(1L)).thenReturn(Optional.of(existing));

        websiteService.deleteWebsite(1L);
        verify(websiteRepository).delete(existing);
    }
}
