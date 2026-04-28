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
class AnomalyDetectorTests {

    @Autowired private AnomalyDetector detector;
    @Autowired private ProfileStore store;

    private static final String CHROME_UA =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";

    private RequestSnapshot browserLike(String client, long ts) {
        return new RequestSnapshot(
                client,
                List.of("Host", "Connection", "User-Agent", "Accept", "Accept-Language",
                        "Accept-Encoding", "Cookie"),
                CHROME_UA,
                "ko-KR,en;q=0.8",
                true,
                -1, 0,
                ts
        );
    }

    private RequestSnapshot curlLike(String client, long ts) {
        return new RequestSnapshot(
                client,
                List.of("Host", "User-Agent", "Accept"),
                "curl/8.4.0",
                null,
                false,
                -1, 0,
                ts
        );
    }

    @BeforeEach
    void reset() {
        store.clear();
    }

    @Test
    void normal_browser_sequence_passes() {
        long t0 = 1_000_000_000L;
        for (int i = 0; i < 10; i++) {
            Verdict v = detector.evaluate(browserLike("alice", t0 + i * 800L));
            assertTrue(v.allow(), "iteration " + i + " denied: " + v.reasons());
        }
    }

    @Test
    void curl_like_with_minimal_headers_does_not_trigger_browser_rules() {
        // curl UA is not "browser-like" so accept-language penalty should not fire
        Verdict v = detector.evaluate(curlLike("bob", 1_000_000_000L));
        assertTrue(v.allow(), "curl는 별도 룰 대상이 아니어야: " + v.reasons());
    }

    @Test
    void browser_ua_without_accept_language_is_flagged() {
        RequestSnapshot s = new RequestSnapshot(
                "carol",
                List.of("Host", "User-Agent", "Accept"),
                CHROME_UA, null, false, -1, 0, 1L);
        Verdict v = detector.evaluate(s);
        assertFalse(v.allow());
        assertTrue(v.reasons().stream().anyMatch(r -> r.contains("accept-language")));
    }

    @Test
    void content_length_mismatch_is_blocked() {
        RequestSnapshot s = new RequestSnapshot(
                "dave",
                List.of("Host", "User-Agent", "Accept", "Accept-Language", "Cookie", "Content-Length"),
                CHROME_UA, "en-US", true,
                100, 30, 1L);
        Verdict v = detector.evaluate(s);
        assertFalse(v.allow());
        assertTrue(v.reasons().stream().anyMatch(r -> r.contains("content-length mismatch")));
    }

    @Test
    void burst_rhythm_after_warmup_is_flagged() {
        long t0 = 2_000_000_000L;
        for (int i = 0; i < 6; i++) {
            assertTrue(detector.evaluate(browserLike("eve", t0 + i * 1000L)).allow());
        }
        Verdict v = detector.evaluate(browserLike("eve", t0 + 5 * 1000L + 5));
        assertFalse(v.allow());
        assertTrue(v.reasons().stream().anyMatch(r -> r.contains("burst rhythm")));
    }

    @Test
    void header_order_with_first_not_host_is_penalized() {
        RequestSnapshot s = new RequestSnapshot(
                "frank",
                List.of("User-Agent", "Host", "Accept", "Accept-Language", "Cookie"),
                CHROME_UA, "en-US", true, -1, 0, 1L);
        Verdict v = detector.evaluate(s);
        assertTrue(v.score() > 0, "score=" + v.score());
        assertTrue(v.reasons().stream().anyMatch(r -> r.contains("first header not Host")),
                "reasons=" + v.reasons());
    }

    @Test
    void same_browser_shape_yields_same_fingerprint() {
        Verdict a = detector.evaluate(browserLike("g1", 100L));
        Verdict b = detector.evaluate(browserLike("g2", 200L));
        assertEquals(a.fingerprint(), b.fingerprint());
    }

    @Test
    void different_ua_shapes_yield_different_fingerprints() {
        Verdict a = detector.evaluate(browserLike("h1", 100L));
        Verdict b = detector.evaluate(curlLike("h2", 200L));
        assertNotEquals(a.fingerprint(), b.fingerprint());
    }
}
