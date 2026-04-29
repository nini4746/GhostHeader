package com.ghost.detect;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

@Component
public class ProfileStore {

    private static final Logger log = LoggerFactory.getLogger(ProfileStore.class);

    private final BoundedProfileMap byClient;
    private final BoundedProfileMap byFingerprint;
    private final long ttlMs;

    public ProfileStore(@Value("${ghost.store.max-clients:50000}") int maxClients,
                        @Value("${ghost.store.max-fingerprints:5000}") int maxFingerprints,
                        @Value("${ghost.store.ttl-ms:3600000}") long ttlMs) {
        this.byClient = new BoundedProfileMap(maxClients);
        this.byFingerprint = new BoundedProfileMap(maxFingerprints);
        this.ttlMs = ttlMs;
    }

    public Profile clientProfile(String clientToken) {
        synchronized (byClient) {
            return byClient.computeIfAbsent(clientToken, k -> new Profile());
        }
    }

    public Profile fingerprintProfile(String fingerprint) {
        synchronized (byFingerprint) {
            return byFingerprint.computeIfAbsent(fingerprint, k -> new Profile());
        }
    }

    public int knownClients() { synchronized (byClient) { return byClient.size(); } }
    public int knownFingerprints() { synchronized (byFingerprint) { return byFingerprint.size(); } }

    public void clear() {
        synchronized (byClient) { byClient.clear(); }
        synchronized (byFingerprint) { byFingerprint.clear(); }
    }

    @Scheduled(fixedDelayString = "${ghost.store.sweep-interval-ms:60000}")
    public void sweepIdle() {
        long cutoff = System.currentTimeMillis() - ttlMs;
        int removed = sweep(byClient, cutoff) + sweep(byFingerprint, cutoff);
        if (removed > 0) log.info("ghost profile sweep removed {} idle entries (ttlMs={})", removed, ttlMs);
    }

    private int sweep(Map<String, Profile> map, long cutoff) {
        int removed = 0;
        synchronized (map) {
            Iterator<Map.Entry<String, Profile>> it = map.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<String, Profile> e = it.next();
                long last = e.getValue().lastSeenMs();
                if (last >= 0 && last < cutoff) {
                    it.remove();
                    removed++;
                }
            }
        }
        return removed;
    }

    private static final class BoundedProfileMap extends LinkedHashMap<String, Profile> {
        private final int max;

        BoundedProfileMap(int max) {
            super(16, 0.75f, true);
            this.max = max;
        }

        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Profile> eldest) {
            return size() > max;
        }
    }
}
