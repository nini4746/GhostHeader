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
        long timestampMs,
        String acceptEncoding,
        String secFetchSite
) {
    /** Backwards-compatible constructor — defaults the additional dimensions to null. */
    public RequestSnapshot(String clientToken,
                           List<String> orderedHeaderNames,
                           String userAgent,
                           String acceptLanguage,
                           boolean hasCookie,
                           long contentLengthHeader,
                           long actualBodyBytes,
                           long timestampMs) {
        this(clientToken, orderedHeaderNames, userAgent, acceptLanguage, hasCookie,
                contentLengthHeader, actualBodyBytes, timestampMs, null, null);
    }

    public boolean missingUserAgent() { return userAgent == null || userAgent.isBlank(); }
    public boolean missingAcceptLanguage() { return acceptLanguage == null || acceptLanguage.isBlank(); }
    public boolean missingAcceptEncoding() { return acceptEncoding == null || acceptEncoding.isBlank(); }
    public boolean missingSecFetch() { return secFetchSite == null || secFetchSite.isBlank(); }
    public boolean contentLengthMismatch() {
        return contentLengthHeader >= 0 && contentLengthHeader != actualBodyBytes;
    }
    public int headerCount() { return orderedHeaderNames.size(); }
}
