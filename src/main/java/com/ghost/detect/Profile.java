package com.ghost.detect;

import java.util.concurrent.atomic.AtomicLong;

public class Profile {

    private final Object lock = new Object();
    private long count = 0;
    private long lastSeenMs = -1;
    private double intervalMean = 0;
    private double intervalM2 = 0;
    private final AtomicLong totalRequests = new AtomicLong();

    public void observe(long nowMs) {
        synchronized (lock) {
            totalRequests.incrementAndGet();
            if (lastSeenMs >= 0) {
                long delta = nowMs - lastSeenMs;
                count++;
                double d = delta - intervalMean;
                intervalMean += d / count;
                intervalM2 += d * (delta - intervalMean);
            }
            lastSeenMs = nowMs;
        }
    }

    public long count() { synchronized (lock) { return count; } }
    public double intervalMean() { synchronized (lock) { return intervalMean; } }
    public double intervalStddev() {
        synchronized (lock) {
            if (count < 2) return 0;
            return Math.sqrt(intervalM2 / (count - 1));
        }
    }
    public long lastSeenMs() { synchronized (lock) { return lastSeenMs; } }
    public long totalRequests() { return totalRequests.get(); }
}
