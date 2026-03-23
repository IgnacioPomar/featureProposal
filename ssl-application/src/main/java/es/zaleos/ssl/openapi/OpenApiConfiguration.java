package es.zaleos.ssl.openapi;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(OpenApiProperties.class)
public class OpenApiConfiguration {

    private final OpenApiProperties properties;

    public OpenApiConfiguration(OpenApiProperties properties) {
        this.properties = properties;
    }

    @Bean
    public OpenAPI sslApplicationOpenAPI() {
        return new OpenAPI().info(new Info()
                .title(properties.getTitle())
                .description(properties.getDescription())
                .version(properties.getVersion()));
    }
}
