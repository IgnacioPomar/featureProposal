package com.example.ssl;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Verifies that the application context and hello endpoint work.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SslApplicationTests {

    @Autowired
    private MockMvc mockMvc;

    /**
     * Ensures the Hello World endpoint responds successfully.
     *
     * @throws Exception when the test client fails
     */
    @Test
    void helloEndpointReturnsExpectedPayload() throws Exception {
        mockMvc.perform(get("/hello"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.message").value("Hello World"));
    }
}
