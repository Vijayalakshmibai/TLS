package com.tlsmonitor.risk;

import com.tlsmonitor.risk.service.ExpiryChecker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.*;

class ExpiryCheckerTest {

    private ExpiryChecker checker;

    @BeforeEach
    void setUp() {
        checker = new ExpiryChecker();
    }

    @Test
    void testCalculateRemainingDays() {
        LocalDateTime future = LocalDateTime.now(ZoneOffset.UTC).plusDays(45);
        long days = checker.calculateRemainingDays(future);
        assertTrue(days >= 44 && days <= 46);
    }

    @Test
    void testCategorizeExpired() {
        assertEquals(ExpiryChecker.ExpiryCategory.EXPIRED, checker.categorize(-1));
        assertEquals(ExpiryChecker.ExpiryCategory.EXPIRED, checker.categorize(-30));
    }

    @Test
    void testCategorizeCritical() {
        assertEquals(ExpiryChecker.ExpiryCategory.CRITICAL, checker.categorize(0));
        assertEquals(ExpiryChecker.ExpiryCategory.CRITICAL, checker.categorize(5));
        assertEquals(ExpiryChecker.ExpiryCategory.CRITICAL, checker.categorize(7));
    }

    @Test
    void testCategorizeHigh() {
        assertEquals(ExpiryChecker.ExpiryCategory.HIGH, checker.categorize(8));
        assertEquals(ExpiryChecker.ExpiryCategory.HIGH, checker.categorize(25));
        assertEquals(ExpiryChecker.ExpiryCategory.HIGH, checker.categorize(30));
    }

    @Test
    void testCategorizeMedium() {
        assertEquals(ExpiryChecker.ExpiryCategory.MEDIUM, checker.categorize(31));
        assertEquals(ExpiryChecker.ExpiryCategory.MEDIUM, checker.categorize(60));
    }

    @Test
    void testCategorizeLow() {
        assertEquals(ExpiryChecker.ExpiryCategory.LOW, checker.categorize(61));
        assertEquals(ExpiryChecker.ExpiryCategory.LOW, checker.categorize(365));
    }

    @Test
    void testIsNotYetValid() {
        LocalDateTime future = LocalDateTime.now(ZoneOffset.UTC).plusDays(10);
        LocalDateTime past = LocalDateTime.now(ZoneOffset.UTC).minusDays(10);
        assertTrue(checker.isNotYetValid(future));
        assertFalse(checker.isNotYetValid(past));
        assertFalse(checker.isNotYetValid(null));
    }
}
