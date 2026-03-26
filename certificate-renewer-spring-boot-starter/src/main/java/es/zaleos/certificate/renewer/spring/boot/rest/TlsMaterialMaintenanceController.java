package es.zaleos.certificate.renewer.spring.boot.rest;

import es.zaleos.certificate.renewer.core.PemActivationResult;
import es.zaleos.certificate.renewer.spring.boot.autoconfigure.CertificateRenewerProperties;
import es.zaleos.certificate.renewer.spring.boot.runtime.TlsMaterialService;
import es.zaleos.certificate.renewer.spring.boot.security.JwsVerificationException;
import es.zaleos.certificate.renewer.spring.boot.security.TlsMaterialJwsVerifier;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.Map;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

/**
 * REST endpoints for remote TLS material management.
 *
 * <p>All active endpoints require a JWS token signed with the currently installed certificate.
 * Each endpoint can be individually disabled via {@code zaleos.certificate.maintenance.*}.
 * The controller itself is only registered when {@code zaleos.certificate.maintenance.enabled=true}.
 */
@RestController
public class TlsMaterialMaintenanceController {

    private static final Log LOG = LogFactory.getLog(TlsMaterialMaintenanceController.class);
    private static final String MAINTENANCE_CLAIM = "zaleos.certificates.maintenance";
    private static final String DEFAULT_TARGET = "web-server";

    private final TlsMaterialService operationService;
    private final TlsMaterialJwsVerifier jwsVerifier;
    private final CertificateRenewerProperties properties;

    public TlsMaterialMaintenanceController(
            TlsMaterialService operationService,
            TlsMaterialJwsVerifier jwsVerifier,
            CertificateRenewerProperties properties
    ) {
        this.operationService = operationService;
        this.jwsVerifier = jwsVerifier;
        this.properties = properties;
    }

    /**
     * Imports TLS material from a folder already present on the server.
     *
     * <p>Request params: {@code sourceDir} (required), {@code password} (optional).
     */
    @PostMapping("${zaleos.certificate.maintenance.import-from-folder.path:/internal/certificates/import-from-folder}")
    public ResponseEntity<Map<String, Object>> importFromFolder(
            @RequestHeader("Authorization") String authorizationHeader,
            @RequestParam(value = "target", required = false, defaultValue = DEFAULT_TARGET) String target,
            @RequestParam("sourceDir") String sourceDir,
            @RequestParam(value = "password", required = false, defaultValue = "") String password
    ) {
        if (!properties.getMaintenance().getImportFromFolder().isEnabled()) {
            return ResponseEntity.notFound().build();
        }
        authenticate(authorizationHeader);

        try {
            PemActivationResult result = operationService.importAndActivate(
                    target,
                    Path.of(sourceDir),
                    null,
                    password.toCharArray(),
                    true
            );
            return ResponseEntity.ok(activationResponse(target, result));
        } catch (IllegalStateException e) {
            return ResponseEntity.status(409).body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            LOG.error("Import from folder failed", e);
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Imports TLS material uploaded as multipart files.
     *
     * <p>Parts: {@code fullchain} (required), {@code privateKey} (required),
     * {@code password} (optional).
     */
    @PostMapping(value = "${zaleos.certificate.maintenance.import-upload.path:/internal/certificates/import-upload}",
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Map<String, Object>> importUpload(
            @RequestHeader("Authorization") String authorizationHeader,
            @RequestParam(value = "target", required = false, defaultValue = DEFAULT_TARGET) String target,
            @RequestParam("fullchain") MultipartFile fullchain,
            @RequestParam("privateKey") MultipartFile privateKey,
            @RequestParam(value = "password", required = false, defaultValue = "") String password
    ) {
        if (!properties.getMaintenance().getImportUpload().isEnabled()) {
            return ResponseEntity.notFound().build();
        }
        authenticate(authorizationHeader);

        if (fullchain.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "fullchain file is empty"));
        }
        if (privateKey.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "privateKey file is empty"));
        }

        Path tempDir = null;
        try {
            tempDir = Files.createTempDirectory("zaleos-upload-");
            Path fullchainPath = tempDir.resolve("fullchain.pem");
            Path privateKeyPath = tempDir.resolve("private-key.pem");
            fullchain.transferTo(fullchainPath);
            privateKey.transferTo(privateKeyPath);

            PemActivationResult result = operationService.importAndActivate(
                    target,
                    tempDir,
                    null,
                    password.toCharArray(),
                    true
            );
            return ResponseEntity.ok(activationResponse(target, result));
        } catch (IllegalStateException e) {
            return ResponseEntity.status(409).body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            LOG.error("Import upload failed", e);
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        } finally {
            deleteQuietly(tempDir);
        }
    }

    /**
     * Restores the previous TLS material from {@code .bak} files.
     */
    @PostMapping("${zaleos.certificate.maintenance.rollback.path:/internal/certificates/rollback}")
    public ResponseEntity<Map<String, Object>> rollback(
            @RequestHeader("Authorization") String authorizationHeader,
            @RequestParam(value = "target", required = false, defaultValue = DEFAULT_TARGET) String target
    ) {
        if (!properties.getMaintenance().getRollback().isEnabled()) {
            return ResponseEntity.notFound().build();
        }
        authenticate(authorizationHeader);

        try {
            operationService.rollback(target, true);
            return ResponseEntity.ok(Map.of("status", "rolled back", "target", target));
        } catch (IllegalStateException e) {
            return ResponseEntity.status(409).body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            LOG.error("Rollback failed", e);
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }

    private void authenticate(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new JwsVerificationException("Missing or malformed Authorization header");
        }
        String token = authorizationHeader.substring(7);
        Map<String, Object> claims = jwsVerifier.verifyAndExtractClaims(token);
        Object maintenanceClaim = claims.get(MAINTENANCE_CLAIM);
        if (!Boolean.TRUE.equals(maintenanceClaim)) {
            throw new JwsVerificationException("Token is missing required claim: " + MAINTENANCE_CLAIM);
        }
    }

    private Map<String, Object> activationResponse(String target, PemActivationResult result) {
        return Map.of(
                "target", target,
                "status", "activated",
                "expirationDate", result.expirationDate() != null ? result.expirationDate().toString() : "unknown"
        );
    }

    private void deleteQuietly(Path dir) {
        if (dir == null) return;
        try (var walk = Files.walk(dir)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                try { Files.deleteIfExists(p); } catch (IOException ignored) {}
            });
        } catch (IOException ignored) {}
    }
}
