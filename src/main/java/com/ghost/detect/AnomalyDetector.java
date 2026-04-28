package com.ghost.detect;

import com.ghost.model.RequestSnapshot;
import com.ghost.model.Verdict;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class AnomalyDetector {

    private final ProfileStore profiles;
    private final double threshold;
    private final long warmupRequests;
    private final long burstThresholdMs;

    public AnomalyDetector(ProfileStore profiles,
                           @Value("${ghost.threshold:5.0}") double threshold,
                           @Value("${ghost.warmup-requests:5}") long warmupRequests,
                           @Value("${ghost.burst-threshold-ms:50}") long burstThresholdMs) {
        this.profiles = profiles;
        this.threshold = threshold;
        this.warmupRequests = warmupRequests;
        this.burstThresholdMs = burstThresholdMs;
    }

    public Verdict evaluate(RequestSnapshot s) {
        String fp = Fingerprint.of(s);
        List<String> reasons = new ArrayList<>();
        double score = 0;

        if (s.contentLengthMismatch()) {
            reasons.add("content-length mismatch (header=" + s.contentLengthHeader()
                    + " body=" + s.actualBodyBytes() + ")");
            score += 10.0;
        }
        if (s.missingUserAgent()) {
            reasons.add("missing user-agent");
            score += 3.0;
        }
        boolean uaIsBrowserShape = uaIsBrowser(s.userAgent());
        if (uaIsBrowserShape && s.missingAcceptLanguage()) {
            reasons.add("browser UA without accept-language");
            score += 4.0;
        }
        if (uaIsBrowserShape && !s.hasCookie() && s.headerCount() < 6) {
            reasons.add("browser UA but minimal headers and no cookie");
            score += 2.5;
        }
        score += headerOrderPenalty(s, uaIsBrowserShape, reasons);

        Profile clientProfile = profiles.clientProfile(s.clientToken());
        if (clientProfile.totalRequests() >= warmupRequests && clientProfile.lastSeenMs() >= 0) {
            long delta = s.timestampMs() - clientProfile.lastSeenMs();
            if (delta >= 0 && delta < burstThresholdMs) {
                reasons.add("burst rhythm (" + delta + "ms < " + burstThresholdMs + "ms)");
                score += 4.0;
            }
            double mean = clientProfile.intervalMean();
            double sd = clientProfile.intervalStddev();
            if (sd > 0 && mean > 0) {
                double z = Math.abs(delta - mean) / sd;
                if (z > 4.0) {
                    reasons.add(String.format("interval z-score %.2f", z));
                    score += Math.min(3.0, z - 4.0);
                }
            }
        }

        clientProfile.observe(s.timestampMs());
        profiles.fingerprintProfile(fp).observe(s.timestampMs());

        if (score >= threshold) return Verdict.deny(score, reasons, fp);
        return Verdict.allow(score, fp);
    }

    private boolean uaIsBrowser(String ua) {
        if (ua == null) return false;
        String l = ua.toLowerCase();
        return l.contains("mozilla") && (l.contains("chrome") || l.contains("safari") || l.contains("firefox"));
    }

    private double headerOrderPenalty(RequestSnapshot s, boolean browserUa, List<String> reasons) {
        if (!browserUa) return 0;
        // Real browsers send Host first, then User-Agent or Accept early.
        List<String> ordered = s.orderedHeaderNames();
        if (ordered.isEmpty()) return 0;
        String first = ordered.get(0).toLowerCase();
        if (!first.equals("host") && !first.startsWith(":")) {
            reasons.add("first header not Host (" + first + ")");
            return 2.0;
        }
        return 0;
    }
}
