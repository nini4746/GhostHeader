package com.ghost.detect.rules;

import com.ghost.detect.DetectionRule;
import com.ghost.detect.Profile;
import com.ghost.model.RequestSnapshot;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RhythmRules {

    @Bean
    public DetectionRule burstRhythmRule(
            @Value("${ghost.rules.burst.weight:6.0}") double weight,
            @Value("${ghost.warmup-requests:5}") long warmup,
            @Value("${ghost.burst-threshold-ms:50}") long burstThresholdMs) {
        return new DetectionRule() {
            @Override public String name() { return "burst_rhythm"; }
            @Override public Result apply(RequestSnapshot s, Profile.Snapshot snap) {
                if (snap == null || snap.totalRequests() < warmup || snap.lastSeenMs() < 0) return Result.NONE;
                long delta = s.timestampMs() - snap.lastSeenMs();
                if (delta < 0 || delta >= burstThresholdMs) return Result.NONE;
                return new Result(weight, "burst rhythm (" + delta + "ms < " + burstThresholdMs + "ms)");
            }
        };
    }

    @Bean
    public DetectionRule zScoreRhythmRule(
            @Value("${ghost.warmup-requests:5}") long warmup,
            @Value("${ghost.z-score-cutoff:4.0}") double cutoff,
            @Value("${ghost.z-score-max-add:3.0}") double maxAdd,
            @Value("${ghost.min-stddev-ms:1.0}") double minStddev) {
        return new DetectionRule() {
            @Override public String name() { return "z_score_rhythm"; }
            @Override public Result apply(RequestSnapshot s, Profile.Snapshot snap) {
                if (snap == null || snap.totalRequests() < warmup || snap.lastSeenMs() < 0) return Result.NONE;
                long delta = s.timestampMs() - snap.lastSeenMs();
                double mean = snap.intervalMean();
                if (mean <= 0) return Result.NONE;
                double sd = Math.max(minStddev, snap.intervalStddev());
                double z = Math.abs(delta - mean) / sd;
                if (z <= cutoff) return Result.NONE;
                return new Result(Math.min(maxAdd, z - cutoff), String.format("interval z-score %.2f", z));
            }
        };
    }
}
