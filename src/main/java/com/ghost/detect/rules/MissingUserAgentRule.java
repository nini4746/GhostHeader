package com.ghost.detect.rules;

import com.ghost.detect.DetectionRule;
import com.ghost.detect.Profile;
import com.ghost.model.RequestSnapshot;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class MissingUserAgentRule implements DetectionRule {
    private final double weight;

    public MissingUserAgentRule(@Value("${ghost.rules.missing-ua.weight:3.0}") double weight) {
        this.weight = weight;
    }

    @Override public String name() { return "missing_user_agent"; }

    @Override
    public Result apply(RequestSnapshot s, Profile.Snapshot ignored) {
        if (!s.missingUserAgent()) return Result.NONE;
        return new Result(weight, "missing user-agent");
    }
}
