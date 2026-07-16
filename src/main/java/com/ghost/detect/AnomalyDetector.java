package com.ghost.detect;

import com.ghost.model.RequestSnapshot;
import com.ghost.model.Verdict;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Aggregates DetectionRule beans into a single verdict. Rules are pluggable via Spring DI;
 * adding a new rule = adding a new bean of type DetectionRule, no code change here.
 *
 * The threshold is sourced from {@link DynamicThreshold} so it can adapt to traffic
 * conditions and accept manual overrides.
 */
@Service
public class AnomalyDetector {

    private final ProfileStore profiles;
    private final List<DetectionRule> rules;
    private final DynamicThreshold threshold;
    private final ResponsePolicy policy;

    public AnomalyDetector(ProfileStore profiles,
                           List<DetectionRule> rules,
                           DynamicThreshold threshold,
                           ResponsePolicy policy) {
        this.profiles = profiles;
        this.rules = List.copyOf(rules);
        this.threshold = threshold;
        this.policy = policy;
    }

    public Verdict evaluate(RequestSnapshot s) {
        String fp = Fingerprint.of(s);
        List<String> reasons = new ArrayList<>();
        double score = 0;

        Profile clientProfile = profiles.clientProfile(s.clientToken());
        Profile.Snapshot snap = clientProfile.snapshot();

        for (DetectionRule rule : rules) {
            DetectionRule.Result r = rule.apply(s, snap);
            if (r.score() > 0) {
                score += r.score();
                if (r.reason() != null) reasons.add(r.reason());
            }
        }

        clientProfile.observe(s.timestampMs());
        profiles.fingerprintProfile(fp).observe(s.timestampMs());

        Verdict.Action action = policy.actionFor(score, threshold.currentThreshold());
        // Feed the EMA on any anomalous outcome (delay/decoy/block), not just block,
        // so the adaptive threshold still tracks the real anomaly rate.
        threshold.recordOutcome(action != Verdict.Action.ALLOW);
        return Verdict.of(action, score, reasons, fp);
    }

    public DynamicThreshold thresholdComponent() { return threshold; }
}
