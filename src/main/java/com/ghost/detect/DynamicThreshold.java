package com.ghost.detect;

import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Adjusts the verdict threshold dynamically using an EMA of deny ratio.
 * High deny ratio -> attack in progress -> lower threshold so borderline
 * requests get blocked. Low deny ratio -> mostly legit traffic -> raise
 * threshold a little to reduce false positives.
 *
 * Manual override via {@link #override(Double)} (e.g., from an admin endpoint)
 * disables auto-adjustment until {@link #clearOverride()}.
 */
@Component
public class DynamicThreshold {

    private final double base;
    private final double min;
    private final double max;
    private final double alpha;
    private final double sensitivity;

    private final AtomicLong currentBits;
    private final AtomicLong denyEmaBits;
    private volatile Double override;

    public DynamicThreshold(MeterRegistry meters,
                            @Value("${ghost.threshold:5.0}") double base,
                            @Value("${ghost.threshold.min:2.5}") double min,
                            @Value("${ghost.threshold.max:8.0}") double max,
                            @Value("${ghost.threshold.ema-alpha:0.05}") double alpha,
                            @Value("${ghost.threshold.sensitivity:6.0}") double sensitivity) {
        if (min > base || base > max) {
            throw new IllegalArgumentException("threshold bounds invalid: min=" + min + " base=" + base + " max=" + max);
        }
        this.base = base;
        this.min = min;
        this.max = max;
        this.alpha = Math.min(1.0, Math.max(0.0, alpha));
        this.sensitivity = Math.max(0.0, sensitivity);
        this.currentBits = new AtomicLong(Double.doubleToRawLongBits(base));
        this.denyEmaBits = new AtomicLong(Double.doubleToRawLongBits(0.0));
        meters.gauge("ghost.threshold.current", this, DynamicThreshold::currentThreshold);
        meters.gauge("ghost.threshold.deny_rate_ema", this, DynamicThreshold::denyRateEma);
    }

    public double currentThreshold() {
        Double o = override;
        if (o != null) return o;
        return Double.longBitsToDouble(currentBits.get());
    }

    public double denyRateEma() {
        return Double.longBitsToDouble(denyEmaBits.get());
    }

    /** Feed a verdict outcome (1.0 = deny, 0.0 = allow). Recomputes EMA + threshold. */
    public void recordOutcome(boolean denied) {
        double sample = denied ? 1.0 : 0.0;
        double newEma;
        while (true) {
            long bits = denyEmaBits.get();
            double prev = Double.longBitsToDouble(bits);
            newEma = alpha * sample + (1 - alpha) * prev;
            if (denyEmaBits.compareAndSet(bits, Double.doubleToRawLongBits(newEma))) break;
        }
        // shape: when deny rate is high, push threshold lower (proportional to sensitivity).
        // shift = sensitivity * (denyRate - 0.05). >5% deny rate => lower threshold.
        double shift = sensitivity * (newEma - 0.05);
        double next = Math.max(min, Math.min(max, base - shift));
        currentBits.set(Double.doubleToRawLongBits(next));
    }

    /** Manual override; null clears. */
    public void override(Double value) {
        this.override = value;
    }

    public void clearOverride() {
        this.override = null;
    }

    /** Reset EMA + threshold to base. Intended for tests / admin "panic reset". */
    public void resetState() {
        this.override = null;
        this.denyEmaBits.set(Double.doubleToRawLongBits(0.0));
        this.currentBits.set(Double.doubleToRawLongBits(base));
    }

    public double base() { return base; }
    public double min() { return min; }
    public double max() { return max; }
}
