package com.ghost.detect;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class ProfileStore {

    private final Map<String, Profile> byClient = new ConcurrentHashMap<>();
    private final Map<String, Profile> byFingerprint = new ConcurrentHashMap<>();

    public Profile clientProfile(String clientToken) {
        return byClient.computeIfAbsent(clientToken, k -> new Profile());
    }

    public Profile fingerprintProfile(String fingerprint) {
        return byFingerprint.computeIfAbsent(fingerprint, k -> new Profile());
    }

    public int knownClients() { return byClient.size(); }
    public int knownFingerprints() { return byFingerprint.size(); }

    public void clear() {
        byClient.clear();
        byFingerprint.clear();
    }
}
