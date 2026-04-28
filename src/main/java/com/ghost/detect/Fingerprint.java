package com.ghost.detect;

import com.ghost.model.RequestSnapshot;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

public final class Fingerprint {

    private Fingerprint() {}

    public static String of(RequestSnapshot s) {
        StringBuilder sb = new StringBuilder();
        for (String h : s.orderedHeaderNames()) sb.append(h.toLowerCase()).append('|');
        sb.append("ua:").append(uaShape(s.userAgent())).append('|');
        sb.append("al:").append(s.missingAcceptLanguage() ? "0" : "1").append('|');
        sb.append("ck:").append(s.hasCookie() ? "1" : "0");
        return sha1(sb.toString()).substring(0, 16);
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

    private static String sha1(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            return HexFormat.of().formatHex(md.digest(s.getBytes()));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
