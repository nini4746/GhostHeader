package com.ghost.detect;

import com.ghost.model.RequestSnapshot;
import com.ghost.model.Verdict;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Aggregates DetectionRule beans into a single verdict. Rules are pluggable via Spring DI;
 * adding a new rule = adding a new bean of type DetectionRule, no code change here.
 */
@Service
public class AnomalyDetector {

    private final ProfileStore profiles;
    private final List<DetectionRule> rules;
    private final double threshold;

    public AnomalyDetector(ProfileStore profiles,
                           List<DetectionRule> rules,
                           @Value("${ghost.threshold:5.0}") double threshold) {
        this.profiles = profiles;
        this.rules = List.copyOf(rules);
        this.threshold = threshold;
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

        if (score >= threshold) return Verdict.deny(score, reasons, fp);
        return Verdict.allow(score, reasons, fp);
    }
}
