package com.ghost.web;

import com.ghost.detect.DynamicThreshold;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/admin/threshold")
public class ThresholdController {

    private final DynamicThreshold threshold;

    public ThresholdController(DynamicThreshold threshold) {
        this.threshold = threshold;
    }

    @GetMapping
    public Map<String, Object> get() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("current", threshold.currentThreshold());
        out.put("base", threshold.base());
        out.put("min", threshold.min());
        out.put("max", threshold.max());
        out.put("denyRateEma", threshold.denyRateEma());
        return out;
    }

    @PostMapping("/override")
    public Map<String, Object> override(@RequestParam(name = "value", required = false) Double value) {
        if (value == null) {
            threshold.clearOverride();
        } else {
            threshold.override(value);
        }
        return get();
    }

    @DeleteMapping("/override")
    public Map<String, Object> clear() {
        threshold.clearOverride();
        return get();
    }
}
