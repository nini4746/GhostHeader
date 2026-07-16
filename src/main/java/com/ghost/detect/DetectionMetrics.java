package com.ghost.detect;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class DetectionMetrics {

    private final Counter allowed;
    private final Counter delayed;
    private final Counter decoyed;
    private final Counter denied;
    private final DistributionSummary scoreSummary;

    public DetectionMetrics(MeterRegistry meters) {
        this.allowed = Counter.builder("ghost.verdict.allowed").register(meters);
        this.delayed = Counter.builder("ghost.verdict.delayed").register(meters);
        this.decoyed = Counter.builder("ghost.verdict.decoyed").register(meters);
        this.denied = Counter.builder("ghost.verdict.denied").register(meters);
        this.scoreSummary = DistributionSummary.builder("ghost.score")
                .publishPercentiles(0.5, 0.95, 0.99)
                .distributionStatisticExpiry(Duration.ofMinutes(5))
                .distributionStatisticBufferLength(3)
                .register(meters);
    }

    public void recordAllow(double score) {
        allowed.increment();
        scoreSummary.record(score);
    }

    public void recordDelay(double score) {
        delayed.increment();
        scoreSummary.record(score);
    }

    public void recordDecoy(double score) {
        decoyed.increment();
        scoreSummary.record(score);
    }

    public void recordDeny(double score) {
        denied.increment();
        scoreSummary.record(score);
    }
}
