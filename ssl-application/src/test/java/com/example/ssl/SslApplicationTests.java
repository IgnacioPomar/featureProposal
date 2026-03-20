package com.example.ssl;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(properties = "spring.jpa.hibernate.ddl-auto=create-drop")
class SslApplicationTests {

    @Test
    void contextLoads() {
        // Validates Spring context startup, including generated OpenAPI API wiring.
    }
}
