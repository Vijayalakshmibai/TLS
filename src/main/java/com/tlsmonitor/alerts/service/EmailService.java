package com.tlsmonitor.alerts.service;

import com.tlsmonitor.alerts.entity.Alert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private static final Logger log = LoggerFactory.getLogger(EmailService.class);

    private final JavaMailSender mailSender;

    public EmailService(@Autowired(required = false) JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    public boolean sendAlertEmail(String recipient, Alert alert) {
        if (mailSender == null) {
            log.info("Email alerts disabled (JavaMailSender not configured). Alert logged: [{}] {} - {}",
                    alert.getSeverity(), alert.getDomain(), alert.getMessage());
            return true;
        }

        try {
            SimpleMailMessage message = new SimpleMailMessage();
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
}
