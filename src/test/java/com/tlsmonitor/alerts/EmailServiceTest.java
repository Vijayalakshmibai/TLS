package com.tlsmonitor.alerts;

import com.tlsmonitor.alerts.entity.Alert;
import com.tlsmonitor.alerts.service.EmailService;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mail.MailSendException;
import org.springframework.mail.javamail.JavaMailSender;

import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@DisplayName("EmailService Unit Tests")
class EmailServiceTest {

    @Test
    @DisplayName("Should return false when SMTP credentials are not configured")
    void shouldReturnFalseWhenSmtpUnconfigured() {
        JavaMailSender mailSender = mock(JavaMailSender.class);
        EmailService emailService = new EmailService(mailSender, "", "");
        Alert alert = new Alert(1L, "example.com", "EXPIRED", "CRITICAL", "Expired cert");

        assertFalse(emailService.isSmtpConfigured());
        assertFalse(emailService.sendPdfReportEmail("admin@example.com", alert, new byte[]{1, 2, 3}, "report.pdf"));
        verify(mailSender, never()).send(any(MimeMessage.class));
    }

    @Test
    @DisplayName("Should send MIME message with PDF attachment when SMTP is configured")
    void shouldSendPdfReportEmailWhenConfigured() {
        JavaMailSender mailSender = mock(JavaMailSender.class);
        MimeMessage mimeMessage = new MimeMessage(Session.getInstance(new Properties()));
        when(mailSender.createMimeMessage()).thenReturn(mimeMessage);

        EmailService emailService = new EmailService(mailSender, "sender@gmail.com", "app-password");
        Alert alert = new Alert(1L, "example.com", "CRITICAL_RISK", "CRITICAL", "Risk score 90/100");

        boolean result = emailService.sendPdfReportEmail(
                "recipient@gmail.com",
                alert,
                "%PDF-1.4 test".getBytes(),
                "TLS_Security_Report_example.com.pdf"
        );

        assertTrue(result);
        verify(mailSender, times(1)).send(mimeMessage);
    }

    @Test
    @DisplayName("Should return false when SMTP delivery fails")
    void shouldReturnFalseOnMailSendException() {
        JavaMailSender mailSender = mock(JavaMailSender.class);
        MimeMessage mimeMessage = new MimeMessage(Session.getInstance(new Properties()));
        when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
        doThrow(new MailSendException("SMTP connection refused")).when(mailSender).send(any(MimeMessage.class));

        EmailService emailService = new EmailService(mailSender, "sender@gmail.com", "app-password");
        Alert alert = new Alert(1L, "example.com", "EXPIRED", "CRITICAL", "Expired cert");

        boolean result = emailService.sendPdfReportEmail(
                "recipient@gmail.com",
                alert,
                "%PDF-1.4 test".getBytes(),
                "TLS_Security_Report_example.com.pdf"
        );

        assertFalse(result);
    }
}
