package com.ghost.detect.rules;

import com.ghost.detect.DetectionRule;
import com.ghost.detect.Profile;
import com.ghost.model.RequestSnapshot;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class ContentLengthMismatchRule implements DetectionRule {
    private final double weight;

    public ContentLengthMismatchRule(@Value("${ghost.rules.content-length-mismatch.weight:10.0}") double weight) {
        this.weight = weight;
    }

    @Override public String name() { return "content_length_mismatch"; }

    @Override
    public Result apply(RequestSnapshot s, Profile.Snapshot ignored) {
        if (!s.contentLengthMismatch()) return Result.NONE;
        return new Result(weight, "content-length mismatch (header=" + s.contentLengthHeader()
                + " body=" + s.actualBodyBytes() + ")");
    }
}
