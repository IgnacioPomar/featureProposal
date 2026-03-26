package es.zaleos.ssl.web;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class DemoIndexPageControllerTests {

    @Test
    void indexUsesSingleMainCardAndHighlightsCertificateRenewalDemo() {
        es.zaleos.certificate.renewer.spring.boot.autoconfigure.CertificateRenewerProperties properties =
                new es.zaleos.certificate.renewer.spring.boot.autoconfigure.CertificateRenewerProperties();
        properties.getTargets().computeIfAbsent("web-server", ignored -> new es.zaleos.certificate.renewer.spring.boot.autoconfigure.CertificateRenewerProperties.Target())
                .setOutputDir("./target/ssl");
        properties.getTargets().computeIfAbsent("jwt-signer", ignored -> new es.zaleos.certificate.renewer.spring.boot.autoconfigure.CertificateRenewerProperties.Target())
                .setOutputDir("./target/ssl/jwt-signer");
        properties.getTargets().computeIfAbsent("jwt-verifier", ignored -> new es.zaleos.certificate.renewer.spring.boot.autoconfigure.CertificateRenewerProperties.Target())
                .setOutputDir("./target/ssl/jwt-verifier");
        DemoIndexPageController controller = new DemoIndexPageController(properties, "web-server");

        String html = controller.index().getBody();

        assertThat(html).contains("SSL Application Test Index");
        assertThat(html).contains("Open certificate renewal demo");
        assertThat(html).contains("[Actuator]");
        assertThat(html).contains("[Application]");
        assertThat(html).contains("[OpenAPI]");
        assertThat(html).contains("./mvnw -q -pl ssl-application -am spring-boot:run");
        assertThat(html).contains("--tls.import.target-name");
        assertThat(html).contains("web-server");
        assertThat(html).contains("jwt-signer");
        assertThat(html).contains("jwt-verifier");
        assertThat(html).contains("./target/ssl");
        assertThat(html).contains("zaleos.certificate.targets.web-server.output-dir");
        assertThat(html).contains("spring.ssl.bundle.pem.server.keystore.certificate");
        assertThat(html).contains("spring.ssl.bundle.pem.server.keystore.private-key");
        assertThat(html).contains("server.ssl.bundle=server");
        assertThat(html).doesNotContain("/certificate-maintenance");
    }
}
