package com.ghost.detect;

public class Profile {

    public record Snapshot(long totalRequests, long count, long lastSeenMs,
                           double intervalMean, double intervalStddev) {}

    private final Object lock = new Object();
    private long count = 0;
    private long lastSeenMs = -1;
    private double intervalMean = 0;
    private double intervalM2 = 0;
    private long totalRequests = 0;

    public void observe(long nowMs) {
        synchronized (lock) {
            totalRequests++;
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

    public Snapshot snapshot() {
        synchronized (lock) {
            double sd = count < 2 ? 0.0 : Math.sqrt(intervalM2 / (count - 1));
            return new Snapshot(totalRequests, count, lastSeenMs, intervalMean, sd);
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
    public long totalRequests() { synchronized (lock) { return totalRequests; } }
}
