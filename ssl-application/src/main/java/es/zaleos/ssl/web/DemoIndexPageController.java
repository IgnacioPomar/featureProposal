package es.zaleos.ssl.web;

import es.zaleos.certificate.renewer.spring.boot.autoconfigure.CertificateRenewerProperties;
import java.util.LinkedHashSet;
import java.util.List;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class DemoIndexPageController {

    private final CertificateRenewerProperties certificateProperties;
    private final String defaultTargetName;

    public DemoIndexPageController(
            CertificateRenewerProperties certificateProperties,
            @Value("${app.tls-page.target-name:web-server}") String defaultTargetName
    ) {
        this.certificateProperties = certificateProperties;
        this.defaultTargetName = defaultTargetName;
    }

    @GetMapping(value = "/", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public ResponseEntity<String> index() {
        String availableTargets = String.join(", ", availableTargets());
        String configuredTargets = renderConfiguredTargets();
        String httpsTlsConfiguration = renderHttpsTlsConfiguration();
        String html = """
                <!doctype html>
                <html>
                <head>
                  <meta charset='UTF-8'>
                  <title>SSL Application Test Index</title>
                  <style>
                    body{font-family:Arial,sans-serif;max-width:1120px;margin:24px auto;padding:0 18px;background:#f7f8fb;color:#1f2937}
                    a{color:#0f4c81;text-decoration:none}a:hover{text-decoration:underline}
                    h1{margin-bottom:8px}
                    .card{background:#fff;border:1px solid #d8dee9;border-radius:10px;padding:22px 24px;box-shadow:0 1px 3px rgba(15,23,42,.06)}
                    .muted{color:#526071}
                    .renew-link{display:inline-block;margin:8px 0 18px;padding:12px 16px;border-radius:8px;background:#0f4c81;color:#fff;font-weight:700}
                    .renew-link:hover{background:#0c3d67;text-decoration:none}
                    code,pre{background:#f1f5f9;border-radius:6px}
                    code{padding:2px 4px}
                    pre{padding:12px;overflow:auto;white-space:pre-wrap}
                    ul{margin:10px 0 18px;padding-left:20px}
                    li{margin:8px 0}
                  </style>
                </head>
                <body>
                  <h1>SSL Application Test Index</h1>
                  <p class='muted'>Entry point to test the Maven artifacts from the browser and from the CLI.</p>
                  <div class='card'>
                    <h2>Main demo</h2>
                    <p><a class='renew-link' href='/certificate-renewal'>Open certificate renewal demo</a></p>
                    <p class='muted'>This is the main page to validate good and bad certificate renewal scenarios.</p>
                    <h2>Other browser checks</h2>
                    <ul>
                      <li><strong>[Actuator]</strong> <a href='/actuator/health'>Health endpoint</a>: verifies that the app is alive over HTTPS.</li>
                      <li><strong>[Actuator]</strong> <a href='/actuator/metrics/application.hello.requests'>Hello metrics</a>: confirms Micrometer updates when the hello endpoint is called.</li>
                      <li><strong>[Application]</strong> <a href='/api/tasks'>Task CRUD API</a>: direct generated CRUD endpoint for quick checks with browser or curl.</li>
                      <li><strong>[Application]</strong> <a href='/hello'>Hello endpoint</a>: simple HTTPS endpoint proving the app is serving traffic.</li>
                      <li><strong>[OpenAPI]</strong> <a href='/api-docs'>Raw OpenAPI document</a>: exposed provider contract as JSON.</li>
                      <li><strong>[OpenAPI]</strong> <a href='/swagger-ui.html'>Swagger UI</a>: interactive contract and CRUD browser.</li>
                    </ul>
                    <h2>CLI-only checks</h2>
                    <ul>
                      <li><code>--setup</code>: prepares a new installation and bootstrap material.</li>
                      <li><code>--check-installation</code>: generates the installation verification report.</li>
                      <li><code>--import-tls-material --tls.import.target-name=&lt;target&gt;</code>: imports certificate material from the command line for any configured target.</li>
                    </ul>
                    <p><strong><code>--tls.import.target-name</code></strong> selects which configured target will be replaced. Available values in this demo: <code>%s</code>. If omitted, the default target is <code>%s</code>.</p>
                    <p>The destination replacement logic comes from <code>zaleos.certificate.targets.&lt;target&gt;</code>. In this application the configured destinations are:</p>
                    <ul>
                      %s
                    </ul>
                    <p>The HTTPS server certificate used by Spring Boot is configured separately through these properties:</p>
                    <ul>
                      %s
                    </ul>
                    <p>For <code>web-server</code> both configurations point to the same files, so replacing that target updates the certificate currently served by HTTPS.</p>
                    <p>Full example with Maven wrapper:</p>
                    <pre><code>./mvnw -q -pl ssl-application -am spring-boot:run -Dspring-boot.run.arguments="--import-tls-material --tls.import.target-name=jwt-signer --tls-source-dir=/workspace/testdata/certs/180d-pem --tls-source-password="</code></pre>
                  </div>
                </body>
                </html>
                """.formatted(
                escapeHtml(availableTargets),
                escapeHtml(defaultTargetName),
                configuredTargets,
                httpsTlsConfiguration
        );
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(html);
    }

    private List<String> availableTargets() {
        LinkedHashSet<String> targetNames = new LinkedHashSet<>();
        if (StringUtils.hasText(defaultTargetName)) {
            targetNames.add(defaultTargetName);
        }
        targetNames.add("web-server");
        targetNames.addAll(certificateProperties.getTargets().keySet());
        return targetNames.stream().filter(StringUtils::hasText).toList();
    }

    private String renderConfiguredTargets() {
        StringBuilder html = new StringBuilder();
        for (String targetName : availableTargets()) {
            CertificateRenewerProperties.Target target = certificateProperties.getTargets().get(targetName);
            String outputDir = target != null && StringUtils.hasText(target.getOutputDir())
                    ? target.getOutputDir()
                    : "(resolved from explicit file paths)";
            if ("web-server".equals(targetName)) {
                html.append("<li><code>web-server</code> -> replacement target configured at <code>zaleos.certificate.targets.web-server.output-dir</code> with value <code>")
                        .append(escapeHtml(outputDir))
                        .append("</code>. This is the source of truth used by the replacement service.</li>");
            } else {
                html.append("<li><code>")
                        .append(escapeHtml(targetName))
                        .append("</code> -> replacement target configured under <code>zaleos.certificate.targets.")
                        .append(escapeHtml(targetName))
                        .append(".output-dir</code> with value <code>")
                        .append(escapeHtml(outputDir))
                        .append("</code>.</li>");
            }
        }
        return html.toString();
    }

    private String renderHttpsTlsConfiguration() {
        return "<li><code>server.ssl.bundle=server</code> selects the active Spring SSL bundle.</li>"
                + "<li><code>spring.ssl.bundle.pem.server.keystore.certificate</code> -> <code>file:./target/ssl/fullchain.pem</code>.</li>"
                + "<li><code>spring.ssl.bundle.pem.server.keystore.private-key</code> -> <code>file:./target/ssl/private-key.pem</code>.</li>"
                + "<li>In practice, that means the active HTTPS certificate is read from <code>./target/ssl/fullchain.pem</code> and <code>./target/ssl/private-key.pem</code>.</li>";
    }

    private String escapeHtml(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
