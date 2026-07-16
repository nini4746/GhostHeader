package com.ghost.model;

import java.util.List;

/**
 * Outcome of scoring one request. The {@link Action} grades the response strategy
 * (spec §5: 차단 / 지연 응답 / Decoy) instead of a bare allow/deny bit.
 */
public record Verdict(Action action, double score, List<String> reasons, String fingerprint) {

    /** Response strategy, ordered by escalating severity. */
    public enum Action {
        /** Serve the real response normally. */
        ALLOW,
        /** Serve the real response after a deliberate delay (tarpit). */
        DELAY,
        /** Serve a fake-normal response without touching the real handler. */
        DECOY,
        /** Reject with 403. */
        BLOCK
    }

    /** True only when the request is served normally with no intervention. */
    public boolean allow() {
        return action == Action.ALLOW;
    }

    public static Verdict of(Action action, double score, List<String> reasons, String fp) {
        return new Verdict(action, score, reasons, fp);
    }

    public static Verdict allow(double score, List<String> reasons, String fp) {
        return new Verdict(Action.ALLOW, score, reasons, fp);
    }

    public static Verdict deny(double score, List<String> reasons, String fp) {
        return new Verdict(Action.BLOCK, score, reasons, fp);
    }
}
