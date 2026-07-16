package com.ghost;

import com.ghost.detect.ResponsePolicy;
import com.ghost.model.Verdict.Action;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ResponsePolicyTest {

    // defaults: delay=1.0, decoy=1.4, block=1.8 (× threshold)
    private final ResponsePolicy policy = new ResponsePolicy(1.0, 1.4, 1.8);
    private static final double T = 5.0; // threshold

    @Test
    void below_threshold_is_allow() {
        assertEquals(Action.ALLOW, policy.actionFor(4.99, T)); // ratio 0.998
    }

    @Test
    void at_delay_ratio_is_delay() {
        assertEquals(Action.DELAY, policy.actionFor(5.0, T));  // ratio 1.0
        assertEquals(Action.DELAY, policy.actionFor(6.9, T));  // ratio 1.38
    }

    @Test
    void at_decoy_ratio_is_decoy() {
        assertEquals(Action.DECOY, policy.actionFor(7.0, T));  // ratio 1.4
        assertEquals(Action.DECOY, policy.actionFor(8.9, T));  // ratio 1.78
    }

    @Test
    void at_block_ratio_is_block() {
        assertEquals(Action.BLOCK, policy.actionFor(9.0, T));   // ratio 1.8
        assertEquals(Action.BLOCK, policy.actionFor(20.0, T));  // ratio 4.0
    }

    @Test
    void boundaries_are_inclusive_on_the_upper_action() {
        // exact edges land in the higher-severity band
        assertEquals(Action.DELAY, policy.actionFor(1.0 * T, T));
        assertEquals(Action.DECOY, policy.actionFor(1.4 * T, T));
        assertEquals(Action.BLOCK, policy.actionFor(1.8 * T, T));
    }

    @Test
    void non_positive_threshold_treated_as_block() {
        // avoids div-by-zero; any score with a collapsed threshold is maximally anomalous
        assertEquals(Action.BLOCK, policy.actionFor(0.0, 0.0));
    }

    @Test
    void ratios_must_be_non_decreasing() {
        assertThrows(IllegalArgumentException.class, () -> new ResponsePolicy(1.5, 1.4, 1.8));
        assertThrows(IllegalArgumentException.class, () -> new ResponsePolicy(1.0, 2.0, 1.8));
    }
}
