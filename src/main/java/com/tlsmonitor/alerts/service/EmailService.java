package com.tlsmonitor.alerts.service;

import com.tlsmonitor.alerts.entity.Alert;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private static final Logger log = LoggerFactory.getLogger(EmailService.class);
    private static final String SENDER_DISPLAY_NAME = "Haresh";

    private final JavaMailSender mailSender;
    private final String mailUsername;
    private final String mailPassword;

    @Autowired
    public EmailService(@Autowired(required = false) JavaMailSender mailSender,
                        @Value("${spring.mail.username:}") String mailUsername,
                        @Value("${spring.mail.password:}") String mailPassword) {
        this.mailSender = mailSender;
        this.mailUsername = mailUsername;
        this.mailPassword = mailPassword;
    }

    public EmailService(JavaMailSender mailSender) {
        this(mailSender, "", "");
    }

    public boolean isSmtpConfigured() {
        return mailSender != null
                && mailUsername != null && !mailUsername.isBlank()
                && mailPassword != null && !mailPassword.isBlank();
    }

    public boolean sendAlertEmail(String recipient, Alert alert) {
        if (!isSmtpConfigured()) {
            log.warn("Email alerts skipped (SMTP credentials not configured). Alert: [{}] {} - {}",
                    alert.getSeverity(), alert.getDomain(), alert.getMessage());
            return false;
        }

        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(SENDER_DISPLAY_NAME + " <" + mailUsername + ">");
            message.setTo(recipient);
            message.setSubject("🚨 [" + alert.getSeverity() + "] TLS Security Alert: " + alert.getDomain());
            message.setText("Fresh TLS Certificate Monitoring & Security Alert\n\n" +
                    "Domain: " + alert.getDomain() + "\n" +
                    "Severity: " + alert.getSeverity() + "\n" +
                    "Alert Type: " + alert.getAlertType() + "\n" +
                    "Details: " + alert.getMessage() + "\n\n" +
                    "Timestamp: " + alert.getCreatedAt() + "\n\n" +
                    "Action Required: Please log in to your TLS Monitor dashboard to review findings and take remediation steps.");

            mailSender.send(message);
            log.info("Alert email successfully sent to {} for domain {}", recipient, alert.getDomain());
            return true;
        } catch (Exception e) {
            log.warn("Failed to send alert email to {}: {}", recipient, e.getMessage());
            return false;
        }
    }

    /**
     * Sends a security alert email with the generated PDF assessment report attached.
     * Never reports success when SMTP is unconfigured or delivery fails.
     */
    public boolean sendPdfReportEmail(String recipient, Alert alert, byte[] pdfBytes, String fileName) {
        if (!isSmtpConfigured()) {
            log.warn("Cannot send PDF report email: SMTP credentials (MAIL_USERNAME / MAIL_APP_PASSWORD) are not configured.");
            return false;
        }
        if (recipient == null || recipient.isBlank() || pdfBytes == null || pdfBytes.length == 0) {
            log.warn("Cannot send PDF report email: invalid recipient or empty PDF payload.");
            return false;
        }

        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");
            helper.setFrom(mailUsername, SENDER_DISPLAY_NAME);
            helper.setTo(recipient);
            helper.setSubject("[" + alert.getSeverity() + "] TLS Security PDF Report: " + alert.getDomain());
            helper.setText(
                    "Fresh TLS Certificate Monitoring & Security Report\n\n"
                            + "Domain: " + alert.getDomain() + "\n"
                            + "Alert Type: " + alert.getAlertType() + "\n"
                            + "Severity: " + alert.getSeverity() + "\n"
                            + "Details: " + alert.getMessage() + "\n"
                            + "Alert Created At: " + alert.getCreatedAt() + "\n\n"
                            + "Please find the attached PDF security assessment report.",
                    false
            );
            helper.addAttachment(fileName, new ByteArrayResource(pdfBytes), "application/pdf");

            mailSender.send(mimeMessage);
            log.info("PDF security report emailed successfully to {} for domain {}", recipient, alert.getDomain());
            return true;
        } catch (Exception e) {
            log.error("Failed to send PDF report email to {} for domain {}: {}", recipient, alert.getDomain(), e.getMessage(), e);
            return false;
        }
    }
}
