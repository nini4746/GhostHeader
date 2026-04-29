package com.ghost.detect.rules;

import com.ghost.detect.DetectionRule;
import com.ghost.detect.Profile;
import com.ghost.model.RequestSnapshot;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class BrowserShapeRules {

    static boolean isBrowserShape(String ua) {
        if (ua == null) return false;
        String l = ua.toLowerCase();
        return l.contains("mozilla") && (l.contains("chrome") || l.contains("safari") || l.contains("firefox"));
    }

    @Bean
    public DetectionRule browserMissingAcceptLanguageRule(
            @Value("${ghost.rules.browser-missing-al.weight:4.0}") double weight) {
        return new DetectionRule() {
            @Override public String name() { return "browser_missing_accept_language"; }
            @Override public Result apply(RequestSnapshot s, Profile.Snapshot ignored) {
                if (!isBrowserShape(s.userAgent()) || !s.missingAcceptLanguage()) return Result.NONE;
                return new Result(weight, "browser UA without accept-language");
            }
        };
    }

    @Bean
    public DetectionRule browserMinimalHeadersRule(
            @Value("${ghost.rules.browser-minimal-headers.weight:2.5}") double weight,
            @Value("${ghost.rules.browser-minimal-headers.min-headers:6}") int minHeaders) {
        return new DetectionRule() {
            @Override public String name() { return "browser_minimal_headers"; }
            @Override public Result apply(RequestSnapshot s, Profile.Snapshot ignored) {
                if (!isBrowserShape(s.userAgent()) || s.hasCookie() || s.headerCount() >= minHeaders) return Result.NONE;
                return new Result(weight, "browser UA but minimal headers and no cookie");
            }
        };
    }

    @Bean
    public DetectionRule browserHeaderOrderRule(
            @Value("${ghost.rules.browser-header-order.weight:2.0}") double weight) {
        return new DetectionRule() {
            @Override public String name() { return "browser_header_order"; }
            @Override public Result apply(RequestSnapshot s, Profile.Snapshot ignored) {
                if (!isBrowserShape(s.userAgent())) return Result.NONE;
                List<String> ordered = s.orderedHeaderNames();
                if (ordered.isEmpty()) return Result.NONE;
                String first = ordered.get(0).toLowerCase();
                if (first.equals("host") || first.startsWith(":")) return Result.NONE;
                return new Result(weight, "first header not Host (" + first + ")");
            }
        };
    }
}
