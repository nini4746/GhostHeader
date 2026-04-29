package com.ghost.detect;

import com.ghost.model.RequestSnapshot;

/**
 * Pluggable rule that contributes a score component to a request verdict.
 * Implementations are discovered as Spring beans and consulted in order.
 *
 * Invariants:
 *  - apply() must be deterministic given snapshot + profile snapshot
 *  - score returned must be non-negative; 0 means rule did not fire
 *  - if score > 0, a reason string should be appended to the result
 *  - implementations must not mutate snapshot or profile
 */
public interface DetectionRule {

    record Result(double score, String reason) {
        public static final Result NONE = new Result(0.0, null);
    }

    /** Stable name shown in metrics/logs. */
    String name();

    /**
     * Evaluate a request against this rule. May read profile snapshot but never mutates it.
     *
     * @param request the request being evaluated
     * @param clientProfile snapshot of caller's history (warmup-completed if totalRequests >= warmup)
     * @return Result.NONE if rule didn't fire, otherwise score + reason
     */
    Result apply(RequestSnapshot request, Profile.Snapshot clientProfile);
}
