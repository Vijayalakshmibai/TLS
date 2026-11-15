package com.tlsmonitor.inventory.controller;

import com.tlsmonitor.common.dto.ApiResponse;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.inventory.service.WebsiteService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/websites")
public class WebsiteController {

    private final WebsiteService websiteService;

    public WebsiteController(WebsiteService websiteService) {
        this.websiteService = websiteService;
    }

    @PostMapping
    public ResponseEntity<ApiResponse<Website>> addWebsite(@Valid @RequestBody Website website) {
        Website saved = websiteService.addWebsite(website);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.ok("Website successfully registered", saved));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<List<Website>>> getAllWebsites() {
        List<Website> websites = websiteService.getAllWebsites();
        return ResponseEntity.ok(ApiResponse.ok(websites));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<Website>> getWebsiteById(@PathVariable Long id) {
        Website website = websiteService.getWebsiteById(id);
        return ResponseEntity.ok(ApiResponse.ok(website));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ApiResponse<Website>> updateWebsite(@PathVariable Long id, @RequestBody Website website) {
        Website updated = websiteService.updateWebsite(id, website);
        return ResponseEntity.ok(ApiResponse.ok("Website successfully updated", updated));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> deleteWebsite(@PathVariable Long id) {
        websiteService.deleteWebsite(id);
        return ResponseEntity.ok(ApiResponse.ok("Website successfully deleted", null));
    }
}
