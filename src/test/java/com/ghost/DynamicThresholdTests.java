package com.ghost;

import com.ghost.detect.DynamicThreshold;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DynamicThresholdTests {

    private DynamicThreshold newThreshold() {
        return new DynamicThreshold(new SimpleMeterRegistry(), 5.0, 2.5, 8.0, 0.5, 6.0);
    }

    @Test
    void startsAtBaseValue() {
        DynamicThreshold t = newThreshold();
        assertEquals(5.0, t.currentThreshold(), 0.0001);
    }

    @Test
    void rejectsInvalidBounds() {
        assertThrows(IllegalArgumentException.class,
                () -> new DynamicThreshold(new SimpleMeterRegistry(), 5.0, 6.0, 8.0, 0.1, 1.0));
        assertThrows(IllegalArgumentException.class,
                () -> new DynamicThreshold(new SimpleMeterRegistry(), 5.0, 1.0, 4.0, 0.1, 1.0));
    }

    @Test
    void persistentDeniesLowerThreshold() {
        DynamicThreshold t = newThreshold();
        for (int i = 0; i < 200; i++) t.recordOutcome(true);
        assertTrue(t.currentThreshold() < 5.0, "threshold should drop when deny rate high");
        assertTrue(t.currentThreshold() >= t.min());
    }

    @Test
    void persistentAllowsRaiseThreshold() {
        DynamicThreshold t = newThreshold();
        for (int i = 0; i < 200; i++) t.recordOutcome(false);
        assertTrue(t.currentThreshold() >= 5.0, "threshold should creep upward when no denies");
        assertTrue(t.currentThreshold() <= t.max());
    }

    @Test
    void manualOverrideTakesPrecedence() {
        DynamicThreshold t = newThreshold();
        t.override(1.0);
        for (int i = 0; i < 100; i++) t.recordOutcome(false);
        assertEquals(1.0, t.currentThreshold(), 0.0001);
        t.clearOverride();
        assertNotEquals(1.0, t.currentThreshold());
    }

    @Test
    void thresholdNeverEscapesBounds() {
        DynamicThreshold t = newThreshold();
        for (int i = 0; i < 1000; i++) t.recordOutcome(true);
        assertTrue(t.currentThreshold() >= t.min() - 1e-9);
        for (int i = 0; i < 1000; i++) t.recordOutcome(false);
        assertTrue(t.currentThreshold() <= t.max() + 1e-9);
    }
}
