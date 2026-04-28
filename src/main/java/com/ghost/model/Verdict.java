package com.ghost.model;

import java.util.List;

public record Verdict(boolean allow, double score, List<String> reasons, String fingerprint) {
    public static Verdict allow(double score, List<String> reasons, String fp) {
        return new Verdict(true, score, reasons, fp);
    }
    public static Verdict deny(double score, List<String> reasons, String fp) {
        return new Verdict(false, score, reasons, fp);
    }
}
