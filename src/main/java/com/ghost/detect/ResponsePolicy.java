package com.ghost.detect;

import com.ghost.model.Verdict.Action;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Maps an anomaly score to a response {@link Action} using multipliers over the
 * live {@link DynamicThreshold}. Ratios (not absolute scores) so the response
 * strategy scales with the same adaptive threshold the verdict uses.
 *
 * ratio = score / threshold:
 *   ratio &lt; delayRatio  -> ALLOW
 *   [delayRatio, decoyRatio) -> DELAY
 *   [decoyRatio, blockRatio) -> DECOY
 *   ratio &gt;= blockRatio  -> BLOCK
 */
@Component
public class ResponsePolicy {

    private final double delayRatio;
    private final double decoyRatio;
    private final double blockRatio;

    public ResponsePolicy(
            @Value("${ghost.response.delay-ratio:1.0}") double delayRatio,
            @Value("${ghost.response.decoy-ratio:1.4}") double decoyRatio,
            @Value("${ghost.response.block-ratio:1.8}") double blockRatio) {
        if (!(delayRatio <= decoyRatio && decoyRatio <= blockRatio)) {
            throw new IllegalArgumentException(
                    "response ratios must be non-decreasing: delay=" + delayRatio
                            + " decoy=" + decoyRatio + " block=" + blockRatio);
        }
        this.delayRatio = delayRatio;
        this.decoyRatio = decoyRatio;
        this.blockRatio = blockRatio;
    }

    public Action actionFor(double score, double threshold) {
        double ratio = threshold <= 0 ? Double.POSITIVE_INFINITY : score / threshold;
        if (ratio >= blockRatio) return Action.BLOCK;
        if (ratio >= decoyRatio) return Action.DECOY;
        if (ratio >= delayRatio) return Action.DELAY;
        return Action.ALLOW;
    }
}
