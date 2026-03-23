package es.zaleos.ssl.cli;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

/**
 * Reads placeholder defaults from the packaged application.yml.
 */
@Component
public class ApplicationYamlDefaults {

    private static final Pattern PLACEHOLDER_PATTERN = Pattern.compile("\\$\\{\\s*([A-Z0-9_]+)\\s*:(.*?)}");

    private final Map<String, String> defaultsByVariable;

    public ApplicationYamlDefaults() {
        this.defaultsByVariable = loadDefaults();
    }

    public boolean hasDefault(String variable) {
        return defaultsByVariable.containsKey(variable);
    }

    public Optional<String> defaultValue(String variable) {
        return Optional.ofNullable(defaultsByVariable.get(variable));
    }

    private Map<String, String> loadDefaults() {
        Map<String, String> map = new LinkedHashMap<>();
        ClassPathResource resource = new ClassPathResource("application.yml");
        if (!resource.exists()) {
            return map;
        }

        try {
            String yaml = new String(resource.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            Matcher matcher = PLACEHOLDER_PATTERN.matcher(yaml);
            while (matcher.find()) {
                String variable = matcher.group(1);
                String value = matcher.group(2);
                map.putIfAbsent(variable, value == null ? "" : value);
            }
            return map;
        } catch (IOException exception) {
            return map;
        }
    }
}
