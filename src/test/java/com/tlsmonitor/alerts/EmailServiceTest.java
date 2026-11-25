package com.tlsmonitor.alerts;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tlsmonitor.alerts.entity.Alert;
import com.tlsmonitor.alerts.service.EmailService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;

@DisplayName("EmailService Unit Tests")
class EmailServiceTest {

    @Test
    @DisplayName("Should fail safely when HTTPS Gmail relay is not configured")
    void shouldReturnFalseWhenRelayIsUnconfigured() {
        EmailService emailService = new EmailService("", "", new ObjectMapper());
        Alert alert = new Alert(1L, "example.com", "EXPIRED", "CRITICAL", "Expired cert");

        assertFalse(emailService.sendPdfReportEmail(
                "recipient@gmail.com", alert, new byte[]{1, 2, 3}, "report.pdf"));
        assertFalse(emailService.sendAlertEmail("recipient@gmail.com", alert));
    }
}
