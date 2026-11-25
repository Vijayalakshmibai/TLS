package com.tlsmonitor.alerts.service;

import com.tlsmonitor.alerts.entity.Alert;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

@Service
public class EmailService {

    private static final Logger log = LoggerFactory.getLogger(EmailService.class);
    private static final String SENDER_DISPLAY_NAME = "Haresh";
    private static final String SENDER_EMAIL = "hesh25012006@gmail.com";

    private final String relayUrl;
    private final String relaySecret;
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient;

    public EmailService(
            @Value("${app.email.relay-url:}") String relayUrl,
            @Value("${app.email.relay-secret:}") String relaySecret,
            ObjectMapper objectMapper) {
        this.relayUrl = relayUrl;
        this.relaySecret = relaySecret;
        this.objectMapper = objectMapper;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(8))
                .followRedirects(HttpClient.Redirect.ALWAYS)
                .build();
    }

    boolean isRelayConfigured() {
        return relayUrl != null && !relayUrl.isBlank()
                && relaySecret != null && !relaySecret.isBlank();
    }

    public boolean sendAlertEmail(String recipient, Alert alert) {
        String body = "Fresh TLS Certificate Monitoring & Security Alert\n\n"
                + "Domain: " + alert.getDomain() + "\n"
                + "Severity: " + alert.getSeverity() + "\n"
                + "Alert Type: " + alert.getAlertType() + "\n"
                + "Details: " + alert.getMessage() + "\n"
                + "Timestamp: " + alert.getCreatedAt();
        return send(recipient, "🚨 [" + alert.getSeverity() + "] TLS Security Alert: " + alert.getDomain(),
                body, null, null);
    }

    public boolean sendPdfReportEmail(String recipient, Alert alert, byte[] pdfBytes, String fileName) {
        if (pdfBytes == null || pdfBytes.length == 0) {
            log.error("Cannot send PDF report: generated PDF is empty.");
            return false;
        }
        String body = "Fresh TLS Certificate Monitoring & Security Report\n\n"
                + "Domain: " + alert.getDomain() + "\n"
                + "Alert Type: " + alert.getAlertType() + "\n"
                + "Severity: " + alert.getSeverity() + "\n"
                + "Details: " + alert.getMessage() + "\n"
                + "Alert Created At: " + alert.getCreatedAt() + "\n\n"
                + "Please find the attached PDF security assessment report.";
        return send(recipient, "[" + alert.getSeverity() + "] TLS Security PDF Report: " + alert.getDomain(),
                body, Base64.getEncoder().encodeToString(pdfBytes), fileName);
    }

    private boolean send(String recipient, String subject, String body, String pdfBase64, String fileName) {
        if (!isRelayConfigured()) {
            log.error("Email relay is not configured. Set GMAIL_RELAY_URL and GMAIL_RELAY_SECRET.");
            return false;
        }
        if (recipient == null || recipient.isBlank()) {
            log.error("Cannot send email: recipient is blank.");
            return false;
        }

        try {
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("secret", relaySecret);
            payload.put("to", recipient);
            payload.put("subject", subject);
            payload.put("body", body);
            payload.put("senderName", SENDER_DISPLAY_NAME);
            payload.put("senderEmail", SENDER_EMAIL);
            if (pdfBase64 != null) {
                payload.put("pdfBase64", pdfBase64);
                payload.put("fileName", fileName == null ? "TLS_Security_Report.pdf" : fileName);
            }

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(relayUrl))
                    .timeout(Duration.ofSeconds(25))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(payload)))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() >= 200 && response.statusCode() < 300
                    && response.body() != null && response.body().contains("\"ok\":true")) {
                log.info("Email relay accepted message to {} (HTTP {}).", recipient, response.statusCode());
                return true;
            }

            log.error("Email relay rejected message. HTTP status: {}, response: {}",
                    response.statusCode(), response.body());
            return false;
        } catch (Exception e) {
            log.error("Email relay request failed: {}", e.getMessage(), e);
            return false;
        }
    }
}
