package es.zaleos.ssl.web;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Exposes a basic Hello World endpoint.
 */
@RestController
public class HelloController {

    private final Counter helloRequestCounter;
    private final Timer helloRequestTimer;

    /**
     * Creates the controller and registers custom Micrometer meters.
     *
     * @param meterRegistry Micrometer registry managed by Spring Boot
     */
    public HelloController(MeterRegistry meterRegistry) {
        this.helloRequestCounter = Counter.builder("application.hello.requests")
            .description("Counts Hello World endpoint invocations")
            .register(meterRegistry);
        this.helloRequestTimer = Timer.builder("application.hello.duration")
            .description("Measures Hello World endpoint execution time")
            .register(meterRegistry);
    }

    /**
     * Returns a simple HTTPS response payload.
     *
     * @return response data
     */
    @GetMapping("/hello")
    public Map<String, String> hello() {
        return helloRequestTimer.record(() -> {
            helloRequestCounter.increment();
            return Map.of(
                "message", "Hello World"
            );
        });
    }
}
