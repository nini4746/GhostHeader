package com.ghost;

import com.ghost.detect.ProfileStore;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class HttpFlowTests {

    @Autowired private MockMvc mvc;
    @Autowired private ProfileStore store;
    @Autowired private MeterRegistry meters;
    @Autowired private com.ghost.detect.DynamicThreshold threshold;

    @BeforeEach
    void reset() {
        store.clear();
        threshold.resetState();
    }

    @Test
    void browser_like_request_passes_protected_endpoint() throws Exception {
        mvc.perform(get("/api/protected")
                        .header("Host", "ghost.local")
                        .header("Connection", "keep-alive")
                        .header("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/537.36 Chrome/124.0 Safari/537.36")
                        .header("Accept", "application/json")
                        .header("Accept-Language", "en-US")
                        .header("Accept-Encoding", "gzip")
                        .header("Cookie", "session=abc")
                        .header("X-Client-Token", "alice"))
                .andExpect(status().isOk())
                .andExpect(header().exists("X-Ghost-Score"))
                .andExpect(header().exists("X-Ghost-Fingerprint"));
    }

    @Test
    void minimal_browser_ua_without_accept_language_is_blocked() throws Exception {
        mvc.perform(get("/api/protected")
                        .header("Host", "ghost.local")
                        .header("User-Agent", "Mozilla/5.0 Chrome/124.0 Safari/537.36")
                        .header("X-Client-Token", "bob"))
                .andExpect(status().isForbidden())
                .andExpect(header().exists("X-Ghost-Reasons"));
    }

    private static final String CHROME_UA =
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/537.36 Chrome/124.0 Safari/537.36";

    @Test
    void declared_content_length_differs_from_streamed_body_is_flagged() throws Exception {
        // Client declares a 999-byte body but only streams 13 bytes: the mismatch is measured
        // in-line (same request) and must trip the content-length-mismatch signal (+10).
        byte[] body = "payload-bytes".getBytes(); // 13 bytes
        mvc.perform(post("/api/protected")
                        .header("Host", "ghost.local")
                        .header("Connection", "keep-alive")
                        .header("User-Agent", CHROME_UA)
                        .header("Accept", "application/json")
                        .header("Accept-Language", "en-US")
                        .header("Accept-Encoding", "gzip")
                        .header("Sec-Fetch-Site", "same-origin")
                        .header("Cookie", "session=abc")
                        .header("X-Client-Token", "smuggler")
                        .header("Content-Length", "999")
                        .contentType("application/octet-stream")
                        .content(body))
                .andExpect(status().isForbidden())
                .andExpect(header().string("X-Ghost-Reasons", containsString("content-length mismatch")));
    }

    @Test
    void honest_content_length_does_not_trigger_mismatch_rule() throws Exception {
        // Same fully browser-like request, but Content-Length matches the streamed bytes: the
        // mismatch signal must stay silent (no false positive) and the request passes.
        byte[] body = "payload-bytes".getBytes(); // 13 bytes
        mvc.perform(post("/api/protected")
                        .header("Host", "ghost.local")
                        .header("Connection", "keep-alive")
                        .header("User-Agent", CHROME_UA)
                        .header("Accept", "application/json")
                        .header("Accept-Language", "en-US")
                        .header("Accept-Encoding", "gzip")
                        .header("Sec-Fetch-Site", "same-origin")
                        .header("Cookie", "session=abc")
                        .header("X-Client-Token", "honest")
                        .header("Content-Length", "13")
                        .contentType("application/octet-stream")
                        .content(body))
                .andExpect(status().isOk())               // honest body passes...
                .andExpect(header().doesNotExist("X-Ghost-Reasons")); // ...and no rule flagged it as a deny
    }

    @Test
    void verdict_metrics_increment_on_allow_and_deny() throws Exception {
        // allow path
        mvc.perform(get("/api/protected")
                .header("Host", "ghost.local")
                .header("Connection", "keep-alive")
                .header("User-Agent", "Mozilla/5.0 Chrome/124.0 Safari/537.36")
                .header("Accept", "application/json")
                .header("Accept-Language", "en-US")
                .header("Accept-Encoding", "gzip")
                .header("Cookie", "session=abc")
                .header("X-Client-Token", "metric-allow"));
        // deny path (browser UA without accept-language)
        mvc.perform(get("/api/protected")
                .header("User-Agent", "Mozilla/5.0 Chrome/124.0 Safari/537.36")
                .header("X-Client-Token", "metric-deny"));

        assertNotNull(meters.find("ghost.verdict.allowed").counter());
        assertNotNull(meters.find("ghost.verdict.denied").counter());
        assertTrue(meters.find("ghost.verdict.allowed").counter().count() >= 1);
        assertTrue(meters.find("ghost.verdict.denied").counter().count() >= 1);
        assertNotNull(meters.find("ghost.score").summary());
    }
}
