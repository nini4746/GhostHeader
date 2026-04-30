package com.ghost.detect.rules;

import com.ghost.detect.DetectionRule;
import com.ghost.detect.Profile;
import com.ghost.model.RequestSnapshot;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Modern-browser capability rules. Real Chrome/Firefox/Safari always send Accept-Encoding
 * and Sec-Fetch-* metadata; minimalist scripts very rarely do. These signals are weaker
 * than missing Accept-Language but cheap to compute and additive in score.
 */
@Configuration
public class BrowserCapabilityRules {

    static boolean isBrowserShape(String ua) {
        if (ua == null) return false;
        String l = ua.toLowerCase();
        return l.contains("mozilla") && (l.contains("chrome") || l.contains("safari") || l.contains("firefox"));
    }

    @Bean
    public DetectionRule browserMissingAcceptEncodingRule(
            @Value("${ghost.rules.browser-missing-ae.weight:1.5}") double weight) {
        return new DetectionRule() {
            @Override public String name() { return "browser_missing_accept_encoding"; }
            @Override public Result apply(RequestSnapshot s, Profile.Snapshot ignored) {
                if (!isBrowserShape(s.userAgent()) || !s.missingAcceptEncoding()) return Result.NONE;
                return new Result(weight, "browser UA without accept-encoding");
            }
        };
    }

    @Bean
    public DetectionRule browserMissingSecFetchRule(
            @Value("${ghost.rules.browser-missing-sf.weight:2.0}") double weight) {
        return new DetectionRule() {
            @Override public String name() { return "browser_missing_sec_fetch"; }
            @Override public Result apply(RequestSnapshot s, Profile.Snapshot ignored) {
                // Only Chromium/Safari ship Sec-Fetch headers; Firefox added them too.
                // Treat absence as a weak signal - additive, not conclusive.
                if (!isBrowserShape(s.userAgent()) || !s.missingSecFetch()) return Result.NONE;
                return new Result(weight, "browser UA without Sec-Fetch-Site");
            }
        };
    }
}
