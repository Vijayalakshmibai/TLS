package com.tlsmonitor.risk.service;

import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;

@Component
public class ExpiryChecker {

    public enum ExpiryCategory {
        EXPIRED,
        CRITICAL,  // 0 - 7 days
        HIGH,      // 8 - 30 days
        MEDIUM,    // 31 - 60 days
        LOW        // > 60 days
    }

    public long calculateRemainingDays(LocalDateTime expiryDateTime) {
        if (expiryDateTime == null) {
            return -1;
        }
        LocalDate expiryDate = expiryDateTime.toLocalDate();
        LocalDate today = LocalDate.now(ZoneOffset.UTC);
        return ChronoUnit.DAYS.between(today, expiryDate);
    }

    public ExpiryCategory categorize(long remainingDays) {
        if (remainingDays < 0) {
            return ExpiryCategory.EXPIRED;
        } else if (remainingDays <= 7) {
            return ExpiryCategory.CRITICAL;
        } else if (remainingDays <= 30) {
            return ExpiryCategory.HIGH;
        } else if (remainingDays <= 60) {
            return ExpiryCategory.MEDIUM;
        } else {
            return ExpiryCategory.LOW;
        }
    }
}
