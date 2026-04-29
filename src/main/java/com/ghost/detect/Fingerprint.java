package com.ghost.detect;

import com.ghost.model.RequestSnapshot;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

public final class Fingerprint {

    // full SHA-256 (64 hex). 32-bit truncation is rejected because birthday-collision odds (~65k requests)
    // were observed to be too high in load testing; full hash gives 256-bit collision resistance.
    private static final int FINGERPRINT_HEX_LEN = 64;

    private Fingerprint() {}

    public static String of(RequestSnapshot s) {
        StringBuilder sb = new StringBuilder();
        for (String h : s.orderedHeaderNames()) sb.append(h.toLowerCase()).append('|');
        sb.append("hc:").append(headerCountBucket(s.headerCount())).append('|');
        sb.append("ua:").append(uaShape(s.userAgent())).append('|');
        sb.append("al:").append(s.missingAcceptLanguage() ? "0" : "1").append('|');
        sb.append("ck:").append(s.hasCookie() ? "1" : "0").append('|');
        sb.append("clm:").append(s.contentLengthMismatch() ? "1" : "0");
        return sha256(sb.toString()).substring(0, FINGERPRINT_HEX_LEN);
    }

    /*
     * Header count buckets:
     *   bucket 0 (<4):   typical bot floor — curl/wget default ~3 headers
     *   bucket 1 (4-6):  scripted clients (python-requests, go-http) ~5
     *   bucket 2 (7-9):  minimal browser-like requests
     *   bucket 3 (10-13): typical first-page browser request
     *   bucket 4 (>=14): rich browser request (Sec-Fetch-*, Accept-CH, Cookie, etc.)
     * Boundaries set from production trace P5/P25/P50/P95 observations; review when client mix shifts.
     */
    private static int headerCountBucket(int n) {
        if (n < 4) return 0;
        if (n < 7) return 1;
        if (n < 10) return 2;
        if (n < 14) return 3;
        return 4;
    }

    private static String uaShape(String ua) {
        if (ua == null) return "none";
        String lower = ua.toLowerCase();
        if (lower.contains("mozilla") && lower.contains("chrome")) return "chrome-like";
        if (lower.contains("mozilla") && lower.contains("firefox")) return "firefox-like";
        if (lower.contains("mozilla") && lower.contains("safari")) return "safari-like";
        if (lower.contains("curl")) return "curl";
        if (lower.contains("python") || lower.contains("requests")) return "python";
        if (lower.contains("go-http")) return "go-http";
        return "other";
    }

    private static String sha256(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
