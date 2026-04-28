package com.ghost.model;

import java.util.List;

public record RequestSnapshot(
        String clientToken,
        List<String> orderedHeaderNames,
        String userAgent,
        String acceptLanguage,
        boolean hasCookie,
        long contentLengthHeader,
        long actualBodyBytes,
        long timestampMs
) {
    public boolean missingUserAgent() { return userAgent == null || userAgent.isBlank(); }
    public boolean missingAcceptLanguage() { return acceptLanguage == null || acceptLanguage.isBlank(); }
    public boolean contentLengthMismatch() {
        return contentLengthHeader >= 0 && contentLengthHeader != actualBodyBytes;
    }
    public int headerCount() { return orderedHeaderNames.size(); }
}
