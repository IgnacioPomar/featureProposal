package es.zaleos.certificate.renewer.spring.boot.rest;

import static org.assertj.core.api.Assertions.assertThat;

import es.zaleos.certificate.renewer.core.PemActivationResult;
import es.zaleos.certificate.renewer.core.PemTlsImportAndActivateService;
import es.zaleos.certificate.renewer.spring.boot.autoconfigure.CertificateRenewerProperties;
import es.zaleos.certificate.renewer.spring.boot.runtime.TargetPathsResolver;
import es.zaleos.certificate.renewer.spring.boot.runtime.TlsMaterialService;
import es.zaleos.certificate.renewer.spring.boot.runtime.ValidationPolicyResolver;
import es.zaleos.certificate.renewer.spring.boot.security.TlsMaterialJwsVerifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockMultipartFile;

class TlsMaterialMaintenanceControllerTests {

    @Test
    void importFromFolderUsesRequestedTargetAndReturnsIt() {
        RecordingTlsMaterialService operationService = new RecordingTlsMaterialService();
        TlsMaterialMaintenanceController controller = createController(operationService);

        Map<String, Object> body = controller.importFromFolder(
                "Bearer signed-token",
                "jwt-signer",
                "/tmp/demo",
                ""
        ).getBody();

        assertThat(operationService.lastImportedTarget).isEqualTo("jwt-signer");
        assertThat(body).containsEntry("target", "jwt-signer");
        assertThat(body).containsEntry("status", "activated");
    }

    @Test
    void importUploadUsesRequestedTargetInResponse() {
        RecordingTlsMaterialService operationService = new RecordingTlsMaterialService();
        TlsMaterialMaintenanceController controller = createController(operationService);

        MockMultipartFile fullchain = new MockMultipartFile(
                "fullchain",
                "fullchain.pem",
                "application/x-pem-file",
                "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".getBytes(StandardCharsets.UTF_8)
        );
        MockMultipartFile privateKey = new MockMultipartFile(
                "privateKey",
                "private-key.pem",
                "application/x-pem-file",
                "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n".getBytes(StandardCharsets.UTF_8)
        );

        Map<String, Object> body = controller.importUpload(
                "Bearer signed-token",
                "web-server",
                fullchain,
                privateKey,
                ""
        ).getBody();

        assertThat(operationService.lastImportedTarget).isEqualTo("web-server");
        assertThat(body).containsEntry("target", "web-server");
    }

    @Test
    void rollbackUsesRequestedTargetAndReturnsIt() {
        RecordingTlsMaterialService operationService = new RecordingTlsMaterialService();
        TlsMaterialMaintenanceController controller = createController(operationService);

        Map<String, Object> body = controller.rollback("Bearer signed-token", "jwt-verifier").getBody();

        assertThat(operationService.lastRollbackTarget).isEqualTo("jwt-verifier");
        assertThat(body).containsEntry("target", "jwt-verifier");
        assertThat(body).containsEntry("status", "rolled back");
    }

    private TlsMaterialMaintenanceController createController(RecordingTlsMaterialService operationService) {
        CertificateRenewerProperties properties = new CertificateRenewerProperties();
        properties.getMaintenance().setEnabled(true);
        return new TlsMaterialMaintenanceController(
                operationService,
                new AcceptingJwsVerifier(),
                properties
        );
    }

    private static final class AcceptingJwsVerifier implements TlsMaterialJwsVerifier {

        @Override
        public void verify(String jwsCompact) {
            // No-op for focused controller tests.
        }

        @Override
        public Map<String, Object> verifyAndExtractClaims(String jwsCompact) {
            return Map.of("zaleos.certificates.maintenance", true);
        }
    }

    private static final class RecordingTlsMaterialService extends TlsMaterialService {

        private String lastImportedTarget;
        private String lastRollbackTarget;

        private RecordingTlsMaterialService() {
            super(
                    new PemTlsImportAndActivateService(),
                    new TargetPathsResolver(new MockEnvironment(), new CertificateRenewerProperties()),
                    new ValidationPolicyResolver(new CertificateRenewerProperties()),
                    new CertificateRenewerProperties(),
                    new MockEnvironment(),
                    event -> { },
                    null
            );
        }

        @Override
        public PemActivationResult importAndActivate(
                String targetName,
                Path sourcePath,
                Path externalKeyPath,
                char[] sourcePassword,
                boolean fromApi
        ) {
            this.lastImportedTarget = targetName;
            return new PemActivationResult(
                    sourcePath,
                    Path.of("/tmp/" + targetName + "/fullchain.pem"),
                    Path.of("/tmp/" + targetName + "/private-key.pem"),
                    Instant.parse("2035-01-01T00:00:00Z")
            );
        }

        @Override
        public void rollback(String targetName, boolean immediateReload) {
            this.lastRollbackTarget = targetName;
        }
    }
}
