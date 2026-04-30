package com.ghost;

import com.ghost.detect.AnomalyDetector;
import com.ghost.detect.ProfileStore;
import com.ghost.model.RequestSnapshot;
import com.ghost.model.Verdict;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class BrowserCapabilityRulesTest {

    private static final String CHROME =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";

    @Autowired private AnomalyDetector detector;
    @Autowired private ProfileStore store;
    @Autowired private com.ghost.detect.DynamicThreshold threshold;

    @BeforeEach void reset() { store.clear(); threshold.resetState(); }

    @Test
    void browserMissingAcceptEncodingPenalised() {
        RequestSnapshot s = new RequestSnapshot(
                "ae-test",
                List.of("Host", "User-Agent", "Accept", "Accept-Language", "Cookie"),
                CHROME, "ko", true, -1, 0, 1L,
                null, "same-origin");
        Verdict v = detector.evaluate(s);
        assertTrue(v.reasons().stream().anyMatch(r -> r.contains("accept-encoding")),
                "reasons=" + v.reasons());
    }

    @Test
    void browserMissingSecFetchPenalised() {
        RequestSnapshot s = new RequestSnapshot(
                "sf-test",
                List.of("Host", "User-Agent", "Accept", "Accept-Language", "Cookie", "Accept-Encoding"),
                CHROME, "ko", true, -1, 0, 1L,
                "gzip", null);
        Verdict v = detector.evaluate(s);
        assertTrue(v.reasons().stream().anyMatch(r -> r.contains("Sec-Fetch")),
                "reasons=" + v.reasons());
    }

    @Test
    void fullyEquippedBrowserNotPenalisedByCapabilityRules() {
        RequestSnapshot s = new RequestSnapshot(
                "full-test",
                List.of("Host", "User-Agent", "Accept", "Accept-Language", "Cookie",
                        "Accept-Encoding", "Sec-Fetch-Site", "Sec-Fetch-Mode"),
                CHROME, "ko", true, -1, 0, 1L,
                "gzip, deflate, br", "same-origin");
        Verdict v = detector.evaluate(s);
        assertTrue(v.reasons().stream().noneMatch(r -> r.contains("accept-encoding")
                || r.contains("Sec-Fetch")));
    }

    @Test
    void curlNotSubjectToCapabilityRules() {
        RequestSnapshot s = new RequestSnapshot(
                "curl-cap",
                List.of("Host", "User-Agent", "Accept"),
                "curl/8.4.0", null, false, -1, 0, 1L,
                null, null);
        Verdict v = detector.evaluate(s);
        assertTrue(v.reasons().stream().noneMatch(r -> r.contains("accept-encoding")
                || r.contains("Sec-Fetch")));
    }
}
