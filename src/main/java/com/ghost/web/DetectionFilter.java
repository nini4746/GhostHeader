package com.ghost.web;

import com.ghost.detect.AnomalyDetector;
import com.ghost.model.RequestSnapshot;
import com.ghost.model.Verdict;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

@Component
public class DetectionFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(DetectionFilter.class);
    private final AnomalyDetector detector;

    public DetectionFilter(AnomalyDetector detector) {
        this.detector = detector;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest req) {
        String path = req.getRequestURI();
        return !path.startsWith("/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        RequestSnapshot snap = capture(req);
        Verdict v = detector.evaluate(snap);
        res.setHeader("X-Ghost-Score", String.format("%.2f", v.score()));
        res.setHeader("X-Ghost-Fingerprint", v.fingerprint());
        if (!v.allow()) {
            log.info("ghost-deny client={} fp={} score={} reasons={}",
                    snap.clientToken(), v.fingerprint(), v.score(), v.reasons());
            res.setHeader("X-Ghost-Reasons", String.join("; ", v.reasons()));
            res.sendError(HttpServletResponse.SC_FORBIDDEN, "anomalous request");
            return;
        }
        chain.doFilter(req, res);
    }

    private RequestSnapshot capture(HttpServletRequest req) {
        List<String> ordered = new ArrayList<>();
        var names = req.getHeaderNames();
        if (names != null) Collections.list(names).forEach(ordered::add);
        String clientToken = headerOr(req, "X-Client-Token", clientFallback(req));
        long contentLengthHeader = req.getContentLengthLong();
        long bodyBytes = contentLengthHeader < 0 ? 0 : contentLengthHeader;
        String declared = req.getHeader("X-Declared-Body-Bytes");
        if (declared != null) {
            try { bodyBytes = Long.parseLong(declared); } catch (NumberFormatException ignore) {}
        }
        return new RequestSnapshot(
                clientToken,
                ordered,
                req.getHeader("User-Agent"),
                req.getHeader("Accept-Language"),
                req.getHeader("Cookie") != null,
                contentLengthHeader,
                bodyBytes,
                System.currentTimeMillis()
        );
    }

    private String headerOr(HttpServletRequest r, String n, String fallback) {
        String v = r.getHeader(n);
        return (v == null || v.isBlank()) ? fallback : v;
    }

    private String clientFallback(HttpServletRequest req) {
        return "anon-" + UUID.nameUUIDFromBytes((req.getRemoteAddr() + "|" + req.getHeader("User-Agent")).getBytes());
    }
}
