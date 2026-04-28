package com.ghost.web;

import com.ghost.detect.ProfileStore;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class SampleController {

    private final ProfileStore store;

    public SampleController(ProfileStore store) {
        this.store = store;
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of("ok", true,
                "knownClients", store.knownClients(),
                "knownFingerprints", store.knownFingerprints());
    }

    @RequestMapping("/api/protected")
    public Map<String, Object> protectedEndpoint() {
        return Map.of("ok", true);
    }
}
