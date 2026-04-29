package com.ghost.detect;

import com.ghost.model.RequestSnapshot;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

public final class Fingerprint {

    private static final int FINGERPRINT_HEX_LEN = 32;

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
